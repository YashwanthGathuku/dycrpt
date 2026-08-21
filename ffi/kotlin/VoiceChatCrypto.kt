/**
 * Strongly typed Kotlin bindings for VoiceChat Crypto.
 * Flutter/Android talks to this layer only — never to raw key material.
 *
 * Handshake (PQXDH) runs inside the native engine. Shared secrets and
 * private keys are never passed as JNI arguments.
 *
 * Load the native library (libvoicechat_crypto.so) before use.
 */
package com.voicechat.crypto

class VoiceChatCrypto private constructor() {
    companion object {
        init {
            System.loadLibrary("voicechat_crypto")
        }

        const val PROFILE_CLASSICAL_V1: Byte = 1
        const val PROFILE_CLASSICAL_HE_V1: Byte = 2
        const val PROFILE_HYBRID_PQ_V1: Byte = 3

        @JvmStatic external fun nativeProtocolVersion(): Short
        @JvmStatic external fun nativeEngineCreate(deviceId: ByteArray?, profile: Byte): LongArray
        @JvmStatic external fun nativeEngineDestroy(engine: Long): Int
        @JvmStatic external fun nativePublicIdentity(engine: Long): ByteArray
        @JvmStatic external fun nativeGenerateBundle(engine: Long, oneTimeCount: Int): ByteArray
        @JvmStatic external fun nativeEstablishOutbound(
            engine: Long,
            bundle: ByteArray,
            conversation: ByteArray,
            firstPlaintext: ByteArray,
            ad: ByteArray?
        ): Array<ByteArray> // [sessionId16, packet]
        @JvmStatic external fun nativeProcessInbound(
            engine: Long,
            packet: ByteArray,
            conversation: ByteArray,
            ad: ByteArray?
        ): Array<ByteArray> // [sessionId16, firstPlaintext]
        @JvmStatic external fun nativeEncrypt(
            engine: Long,
            sessionId: ByteArray,
            plaintext: ByteArray,
            ad: ByteArray?
        ): ByteArray
        @JvmStatic external fun nativeDecrypt(
            engine: Long,
            sessionId: ByteArray,
            sealed: ByteArray,
            ad: ByteArray?
        ): ByteArray
        @JvmStatic external fun nativeFingerprint(
            publicA: ByteArray,
            publicB: ByteArray,
            deviceA: ByteArray?,
            deviceB: ByteArray?
        ): Array<ByteArray> // [binary32, numericAscii]
        @JvmStatic external fun nativeDeleteSession(engine: Long, sessionId: ByteArray): Int
    }

    class Engine internal constructor(val handle: Long, val publicKey: ByteArray) {
        fun generateBundle(oneTimeCount: Int): ByteArray =
            nativeGenerateBundle(handle, oneTimeCount)

        fun establishOutbound(
            bundle: ByteArray,
            conversation: ByteArray,
            firstPlaintext: ByteArray,
            ad: ByteArray? = null
        ): Pair<ByteArray, ByteArray> {
            val r = nativeEstablishOutbound(handle, bundle, conversation, firstPlaintext, ad)
            return r[0] to r[1]
        }

        fun processInbound(
            packet: ByteArray,
            conversation: ByteArray,
            ad: ByteArray? = null
        ): Pair<ByteArray, ByteArray> {
            val r = nativeProcessInbound(handle, packet, conversation, ad)
            return r[0] to r[1]
        }

        fun encrypt(sessionId: ByteArray, plaintext: ByteArray, ad: ByteArray? = null): ByteArray =
            nativeEncrypt(handle, sessionId, plaintext, ad)

        fun decrypt(sessionId: ByteArray, sealed: ByteArray, ad: ByteArray? = null): ByteArray =
            nativeDecrypt(handle, sessionId, sealed, ad)

        fun deleteSession(sessionId: ByteArray) {
            nativeDeleteSession(handle, sessionId)
        }

        fun close() {
            nativeEngineDestroy(handle)
        }
    }

    fun createEngine(deviceId: ByteArray? = null, profile: Byte = PROFILE_CLASSICAL_V1): Engine {
        val r = nativeEngineCreate(deviceId, profile)
        require(r.size >= 33) { "native create failed" }
        val handle = r[0]
        val pk = ByteArray(32) { i -> r[i + 1].toByte() }
        return Engine(handle, pk)
    }

    fun fingerprint(
        publicA: ByteArray, publicB: ByteArray,
        deviceA: ByteArray? = null, deviceB: ByteArray? = null
    ): Pair<ByteArray, String> {
        val r = nativeFingerprint(publicA, publicB, deviceA, deviceB)
        return r[0] to r[1].toString(Charsets.US_ASCII)
    }
}
