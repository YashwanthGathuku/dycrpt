package com.voicechat.crypto.storage

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Rollback anchor for dycrpt on Android.
 *
 * ## Read this before shipping
 *
 * Android exposes **no** app-accessible hardware monotonic counter. There is no
 * API that gives a value which provably only increases and cannot be reverted
 * by an attacker with the device. Anyone claiming otherwise is describing
 * `setRollbackResistant`, which is about key *deletion*, not counters.
 *
 * So be precise about what this class does and does not buy you.
 *
 * ### What it defends against
 *
 * **Backup/restore rollback.** The counter is sealed with a non-exportable
 * Android Keystore key and written to `noBackupFilesDir`. Neither the Keystore
 * key nor the file participates in Android Backup, Auto Backup, or a
 * device-to-device transfer. Restoring an old app data set therefore yields a
 * counter that cannot be decrypted (Keystore key absent or different), which
 * surfaces to Rust as `VC_STATE_LOST` — terminal, fail-closed, correct.
 *
 * This is the common real-world case: a user restores a backup, or moves to a
 * new phone, and the stale ratchet state must not be reused.
 *
 * ### What it does NOT defend against
 *
 * **An attacker with root or a live-device exploit.** Such an attacker can copy
 * `counter.bin` and the state file together at time T and put both back at time
 * T+n. The Keystore key is still present, the counter still decrypts, and the
 * pair is internally consistent — so the rollback is undetectable by this
 * anchor. Defending against that requires an anchor the attacker does not
 * control: a **server-held counter**.
 *
 * If your threat model includes a compromised device, use
 * [ServerRollbackAnchor] instead and treat this class as unsuitable.
 *
 * ### Failure mode you must handle
 *
 * If the user removes their lock screen, the Keystore key can be invalidated
 * and the counter becomes permanently undecryptable. The engine will report
 * `VC_STATE_LOST`. That is fail-closed and intended — but it is also a real
 * user-facing lockout, and your app must show something better than a crash.
 *
 * Thread-safety: every method is `@Synchronized`. The Rust engine calls these
 * from multiple threads, and the JNI bridge does not add locking of its own.
 */
class VoiceChatRollbackAnchor(private val context: Context) {

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "dycrpt-anchor-seal-v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val VERSION: Byte = 1
        private const val IV_BYTES = 12
    }

    private val counterFile: File
        get() = File(context.noBackupFilesDir, "dycrpt-anchor.v1")

    /** Current committed anchor value. Returns 0 for a never-provisioned device. */
    @Synchronized
    fun current(): Long {
        val file = counterFile
        if (!file.exists()) return 0L
        return decodeSealed(file.readBytes())
    }

    /**
     * Atomically move [expected] to `expected + 1` and return the new value.
     *
     * Returns -1 if the current value is not [expected]; the Rust side treats a
     * negative return as failure. The durable value is not modified on any
     * failure path: the write is temp-file + fsync + atomic rename, so the
     * outcome is never left unknown, which is what the anchor contract demands.
     */
    @Synchronized
    fun compareAndIncrement(expected: Long): Long {
        if (expected < 0) return -1
        val observed = current()
        if (observed != expected) return -1
        val next = expected + 1
        atomicWrite(counterFile, encodeSealed(next))
        return next
    }

    /** Destroy the anchor. Only for deliberate, user-visible device reset. */
    @Synchronized
    fun destroy() {
        counterFile.delete()
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
    }

    private fun sealingKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return gen.generateKey()
    }

    private fun encodeSealed(value: Long): ByteArray {
        val plain = ByteArray(8)
        for (i in 0 until 8) plain[i] = ((value shr (8 * i)) and 0xff).toByte()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, sealingKey())
        val iv = cipher.iv
        require(iv.size == IV_BYTES)
        val ct = cipher.doFinal(plain)
        return ByteArray(1 + IV_BYTES + ct.size).also {
            it[0] = VERSION
            System.arraycopy(iv, 0, it, 1, IV_BYTES)
            System.arraycopy(ct, 0, it, 1 + IV_BYTES, ct.size)
        }
    }

    private fun decodeSealed(blob: ByteArray): Long {
        require(blob.size >= 1 + IV_BYTES + 16) { "corrupt dycrpt anchor" }
        require(blob[0] == VERSION) { "unsupported dycrpt anchor version" }
        val iv = blob.copyOfRange(1, 1 + IV_BYTES)
        val ct = blob.copyOfRange(1 + IV_BYTES, blob.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, sealingKey(), GCMParameterSpec(128, iv))
        val plain = cipher.doFinal(ct)
        require(plain.size == 8) { "corrupt dycrpt anchor payload" }
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (plain[i].toLong() and 0xff)
        return v
    }

    private fun atomicWrite(target: File, bytes: ByteArray) {
        target.parentFile?.mkdirs()
        val temp = File(target.parentFile, ".${target.name}.${System.nanoTime()}.tmp")
        temp.outputStream().use { s ->
            s.write(bytes)
            s.flush()
            s.fd.sync()
        }
        if (!temp.renameTo(target)) {
            temp.delete()
            throw IllegalStateException("unable to persist dycrpt anchor")
        }
    }
}

/**
 * Server-anchored counter — the option that actually survives a compromised
 * device, because the attacker does not hold the counter.
 *
 * This is an interface, not an implementation, because the correctness lives in
 * your backend, not here. The endpoint must:
 *
 * 1. store the counter per (account, device) and increment **atomically** —
 *    a single conditional-update statement, not read-then-write;
 * 2. reject an increment whose `expected` does not match the stored value;
 * 3. never return success unless the write is durably committed;
 * 4. on network failure, leave the client able to **re-read** and learn the
 *    true value. An increment whose outcome is unknown is exactly the state the
 *    anchor contract forbids, so the client must resolve it by re-reading
 *    before returning, and must surface an error rather than guess.
 *
 * Point 4 is the one that is usually got wrong. A timeout after the server
 * committed, treated as failure, desynchronizes the epoch and is
 * indistinguishable from a rollback at the next open.
 */
interface ServerRollbackAnchor {
    /** Committed value; 0 if this device has never been provisioned. */
    fun current(): Long

    /** Atomic CAS from [expected] to `expected + 1`; -1 if it did not apply. */
    fun compareAndIncrement(expected: Long): Long
}
