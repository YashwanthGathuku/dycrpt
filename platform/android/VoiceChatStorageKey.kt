package com.voicechat.crypto.storage

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android host-side key lifecycle for dycrpt EncryptedFileStorage.
 *
 * A non-exportable Android Keystore AES key wraps a random 32-byte data key.
 * Only the data key is passed to Rust, and only for the lifetime of the engine.
 * The wrapped data key may be stored in app-private/no-backup storage because
 * it is useless without the Keystore key. Do NOT place the raw data key in
 * SharedPreferences, Room, logs, backups, or crash reports.
 */
class VoiceChatStorageKey(private val context: Context) {
    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "dycrpt-storage-wrap-v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val VERSION: Byte = 1
        private const val IV_BYTES = 12
        private const val DATA_KEY_BYTES = 32
    }

    private val wrappedKeyFile: File
        get() = File(context.noBackupFilesDir, "dycrpt-storage-key.v1")

    /** Load an existing data key or create/wrap a new one. */
    @Synchronized
    fun loadOrCreate(): ByteArray {
        val wrappingKey = getOrCreateWrappingKey()
        val file = wrappedKeyFile
        if (file.exists()) {
            return unwrap(file.readBytes(), wrappingKey)
        }

        val dataKey = ByteArray(DATA_KEY_BYTES)
        SecureRandom().nextBytes(dataKey)
        try {
            val wrapped = wrap(dataKey, wrappingKey)
            atomicWrite(file, wrapped)
            return dataKey.copyOf()
        } finally {
            dataKey.fill(0)
        }
    }

    /**
     * Delete local wrapped key material. This cryptographically destroys access
     * to EncryptedFileStorage after the caller has also deleted its state file.
     */
    @Synchronized
    fun destroy() {
        wrappedKeyFile.delete()
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(ALIAS)) {
            ks.deleteEntry(ALIAS)
        }
    }

    private fun getOrCreateWrappingKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        val specBuilder = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)

        // StrongBox is useful when present, but availability varies. The caller
        // should log only capability state, never key material.
        if (android.os.Build.VERSION.SDK_INT >= 28) {
            try {
                specBuilder.setIsStrongBoxBacked(true)
                generator.init(specBuilder.build())
                return generator.generateKey()
            } catch (_: Exception) {
                // Recreate generator/spec without StrongBox request below.
            }
        }

        val fallback = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        fallback.init(
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
        return fallback.generateKey()
    }

    private fun wrap(dataKey: ByteArray, wrappingKey: SecretKey): ByteArray {
        require(dataKey.size == DATA_KEY_BYTES)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey)
        val iv = cipher.iv
        require(iv.size == IV_BYTES)
        val ciphertext = cipher.doFinal(dataKey)
        return ByteArray(1 + IV_BYTES + ciphertext.size).also { out ->
            out[0] = VERSION
            System.arraycopy(iv, 0, out, 1, IV_BYTES)
            System.arraycopy(ciphertext, 0, out, 1 + IV_BYTES, ciphertext.size)
        }
    }

    private fun unwrap(blob: ByteArray, wrappingKey: SecretKey): ByteArray {
        require(blob.size >= 1 + IV_BYTES + 16) { "invalid wrapped dycrpt storage key" }
        require(blob[0] == VERSION) { "unsupported wrapped dycrpt storage key version" }
        val iv = blob.copyOfRange(1, 1 + IV_BYTES)
        val ciphertext = blob.copyOfRange(1 + IV_BYTES, blob.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey, GCMParameterSpec(128, iv))
        val key = cipher.doFinal(ciphertext)
        require(key.size == DATA_KEY_BYTES) { "invalid dycrpt storage data key length" }
        return key
    }

    private fun atomicWrite(target: File, bytes: ByteArray) {
        target.parentFile?.mkdirs()
        val temp = File(target.parentFile, ".${target.name}.${System.nanoTime()}.tmp")
        temp.outputStream().use { stream ->
            stream.write(bytes)
            stream.flush()
            stream.fd.sync()
        }
        if (!temp.renameTo(target)) {
            temp.delete()
            throw IllegalStateException("unable to persist wrapped dycrpt storage key")
        }
    }
}
