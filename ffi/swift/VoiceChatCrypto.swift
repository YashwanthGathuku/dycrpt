/**
 * Strongly typed Swift bindings for VoiceChat Crypto.
 * Flutter/iOS talks to this layer only — raw key material never exposed to Dart.
 *
 * Handshake (PQXDH) runs inside the native engine. Shared secrets and
 * private keys are never passed as C arguments.
 *
 * Link against the static/dynamic voicechat_crypto library built for the target.
 */

import Foundation

public enum VcProfile: UInt8 {
    case classicalV1 = 1
    case classicalHeV1 = 2
    case hybridPqV1 = 3
}

public enum VcErrorCode: Int32 {
    case ok = 0
    case invalidArgument = 1
    case cryptoFailure = 2
    case stateError = 3
    case notFound = 4
    case identityChanged = 5
    case limitExceeded = 6
    case internalError = 99
}

public enum VoiceChatCryptoError: Error {
    case native(VcErrorCode)
    case invalidLength
}

public final class CryptoEngine {
    public let handle: UInt64
    public let publicKey: Data

    init(handle: UInt64, publicKey: Data) {
        self.handle = handle
        self.publicKey = publicKey
    }

    deinit {
        _ = vc_engine_destroy(handle)
    }

    public func generateBundle(oneTimeCount: Int) throws -> Data {
        var n = 0
        let rc = vc_generate_bundle(handle, oneTimeCount, nil, &n)
        guard rc == VcErrorCode.invalidArgument.rawValue, n > 0 else {
            throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc) ?? .internalError)
        }
        var buf = [UInt8](repeating: 0, count: n)
        let rc2 = buf.withUnsafeMutableBufferPointer { p in
            var len = n
            let r = vc_generate_bundle(handle, oneTimeCount, p.baseAddress, &len)
            n = len
            return r
        }
        guard rc2 == 0 else {
            throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc2) ?? .internalError)
        }
        return Data(buf.prefix(n))
    }

    public func establishOutbound(
        bundle: Data,
        conversation: Data,
        firstPlaintext: Data,
        ad: Data = Data()
    ) throws -> (sessionId: Data, packet: Data) {
        var sid = [UInt8](repeating: 0, count: 16)
        var n = 0
        let rc = bundle.withUnsafeBytes { b in
            conversation.withUnsafeBytes { c in
                firstPlaintext.withUnsafeBytes { p in
                    ad.withUnsafeBytes { a in
                        sid.withUnsafeMutableBytes { s in
                            vc_establish_outbound(
                                handle,
                                b.bindMemory(to: UInt8.self).baseAddress, b.count,
                                c.bindMemory(to: UInt8.self).baseAddress, c.count,
                                p.bindMemory(to: UInt8.self).baseAddress, p.count,
                                a.bindMemory(to: UInt8.self).baseAddress, a.count,
                                s.bindMemory(to: UInt8.self).baseAddress,
                                nil, &n
                            )
                        }
                    }
                }
            }
        }
        guard rc == VcErrorCode.invalidArgument.rawValue, n > 0 else {
            throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc) ?? .internalError)
        }
        var pkt = [UInt8](repeating: 0, count: n)
        let rc2 = bundle.withUnsafeBytes { b in
            conversation.withUnsafeBytes { c in
                firstPlaintext.withUnsafeBytes { p in
                    ad.withUnsafeBytes { a in
                        sid.withUnsafeMutableBytes { s in
                            pkt.withUnsafeMutableBufferPointer { o in
                                var len = n
                                let r = vc_establish_outbound(
                                    handle,
                                    b.bindMemory(to: UInt8.self).baseAddress, b.count,
                                    c.bindMemory(to: UInt8.self).baseAddress, c.count,
                                    p.bindMemory(to: UInt8.self).baseAddress, p.count,
                                    a.bindMemory(to: UInt8.self).baseAddress, a.count,
                                    s.bindMemory(to: UInt8.self).baseAddress,
                                    o.baseAddress, &len
                                )
                                n = len
                                return r
                            }
                        }
                    }
                }
            }
        }
        guard rc2 == 0 else {
            throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc2) ?? .internalError)
        }
        return (Data(sid), Data(pkt.prefix(n)))
    }

    public func processInbound(
        packet: Data,
        conversation: Data,
        ad: Data = Data()
    ) throws -> (sessionId: Data, firstPlaintext: Data) {
        var sid = [UInt8](repeating: 0, count: 16)
        var n = 256
        var pt = [UInt8](repeating: 0, count: n)
        let rc = packet.withUnsafeBytes { p in
            conversation.withUnsafeBytes { c in
                ad.withUnsafeBytes { a in
                    sid.withUnsafeMutableBytes { s in
                        pt.withUnsafeMutableBufferPointer { o in
                            var len = n
                            let r = vc_process_inbound(
                                handle,
                                p.bindMemory(to: UInt8.self).baseAddress, p.count,
                                c.bindMemory(to: UInt8.self).baseAddress, c.count,
                                a.bindMemory(to: UInt8.self).baseAddress, a.count,
                                s.bindMemory(to: UInt8.self).baseAddress,
                                o.baseAddress, &len
                            )
                            n = len
                            return r
                        }
                    }
                }
            }
        }
        if rc == VcErrorCode.invalidArgument.rawValue {
            pt = [UInt8](repeating: 0, count: n)
            let rc2 = packet.withUnsafeBytes { p in
                conversation.withUnsafeBytes { c in
                    ad.withUnsafeBytes { a in
                        sid.withUnsafeMutableBytes { s in
                            pt.withUnsafeMutableBufferPointer { o in
                                var len = n
                                let r = vc_process_inbound(
                                    handle,
                                    p.bindMemory(to: UInt8.self).baseAddress, p.count,
                                    c.bindMemory(to: UInt8.self).baseAddress, c.count,
                                    a.bindMemory(to: UInt8.self).baseAddress, a.count,
                                    s.bindMemory(to: UInt8.self).baseAddress,
                                    o.baseAddress, &len
                                )
                                n = len
                                return r
                            }
                        }
                    }
                }
            }
            guard rc2 == 0 else {
                throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc2) ?? .internalError)
            }
        } else if rc != 0 {
            throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc) ?? .internalError)
        }
        return (Data(sid), Data(pt.prefix(n)))
    }

    public func encrypt(sessionId: Data, plaintext: Data, ad: Data = Data()) throws -> Data {
        guard sessionId.count == 16 else { throw VoiceChatCryptoError.invalidLength }
        var n = 0
        let rc = sessionId.withUnsafeBytes { s in
            plaintext.withUnsafeBytes { p in
                ad.withUnsafeBytes { a in
                    vc_encrypt(
                        handle,
                        s.bindMemory(to: UInt8.self).baseAddress,
                        p.bindMemory(to: UInt8.self).baseAddress, p.count,
                        a.bindMemory(to: UInt8.self).baseAddress, a.count,
                        nil, &n
                    )
                }
            }
        }
        guard rc == VcErrorCode.invalidArgument.rawValue, n > 0 else {
            throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc) ?? .internalError)
        }
        var buf = [UInt8](repeating: 0, count: n)
        let rc2 = sessionId.withUnsafeBytes { s in
            plaintext.withUnsafeBytes { p in
                ad.withUnsafeBytes { a in
                    buf.withUnsafeMutableBufferPointer { o in
                        var len = n
                        let r = vc_encrypt(
                            handle,
                            s.bindMemory(to: UInt8.self).baseAddress,
                            p.bindMemory(to: UInt8.self).baseAddress, p.count,
                            a.bindMemory(to: UInt8.self).baseAddress, a.count,
                            o.baseAddress, &len
                        )
                        n = len
                        return r
                    }
                }
            }
        }
        guard rc2 == 0 else {
            throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc2) ?? .internalError)
        }
        return Data(buf.prefix(n))
    }

    public func decrypt(sessionId: Data, sealed: Data, ad: Data = Data()) throws -> Data {
        guard sessionId.count == 16 else { throw VoiceChatCryptoError.invalidLength }
        var n = 4096
        var pt = [UInt8](repeating: 0, count: n)
        let rc = sessionId.withUnsafeBytes { s in
            sealed.withUnsafeBytes { c in
                ad.withUnsafeBytes { a in
                    pt.withUnsafeMutableBufferPointer { o in
                        var len = n
                        let r = vc_decrypt(
                            handle,
                            s.bindMemory(to: UInt8.self).baseAddress,
                            c.bindMemory(to: UInt8.self).baseAddress, c.count,
                            a.bindMemory(to: UInt8.self).baseAddress, a.count,
                            o.baseAddress, &len
                        )
                        n = len
                        return r
                    }
                }
            }
        }
        if rc == VcErrorCode.invalidArgument.rawValue {
            pt = [UInt8](repeating: 0, count: n)
            let rc2 = sessionId.withUnsafeBytes { s in
                sealed.withUnsafeBytes { c in
                    ad.withUnsafeBytes { a in
                        pt.withUnsafeMutableBufferPointer { o in
                            var len = n
                            let r = vc_decrypt(
                                handle,
                                s.bindMemory(to: UInt8.self).baseAddress,
                                c.bindMemory(to: UInt8.self).baseAddress, c.count,
                                a.bindMemory(to: UInt8.self).baseAddress, a.count,
                                o.baseAddress, &len
                            )
                            n = len
                            return r
                        }
                    }
                }
            }
            guard rc2 == 0 else {
                throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc2) ?? .internalError)
            }
        } else if rc != 0 {
            throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc) ?? .internalError)
        }
        return Data(pt.prefix(n))
    }
}

public enum VoiceChatCrypto {
    public static var protocolVersion: UInt16 { vc_protocol_version() }

    public static func createEngine(deviceId: Data = Data(), profile: VcProfile = .classicalV1) throws -> CryptoEngine {
        var handle: UInt64 = 0
        var pk = [UInt8](repeating: 0, count: 32)
        let rc = deviceId.withUnsafeBytes { d in
            pk.withUnsafeMutableBufferPointer { p in
                vc_engine_create(
                    d.bindMemory(to: UInt8.self).baseAddress, d.count,
                    profile.rawValue,
                    &handle,
                    p.baseAddress
                )
            }
        }
        guard rc == 0, handle != 0 else {
            throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc) ?? .internalError)
        }
        return CryptoEngine(handle: handle, publicKey: Data(pk))
    }

    public static func fingerprint(
        publicA: Data, publicB: Data,
        deviceA: Data = Data(), deviceB: Data = Data()
    ) throws -> (binary: Data, numeric: String) {
        guard publicA.count == 32, publicB.count == 32 else {
            throw VoiceChatCryptoError.invalidLength
        }
        var bin = [UInt8](repeating: 0, count: 32)
        var num = [UInt8](repeating: 0, count: 64)
        var nlen = 64
        let rc = publicA.withUnsafeBytes { a in
            publicB.withUnsafeBytes { b in
                deviceA.withUnsafeBytes { da in
                    deviceB.withUnsafeBytes { db in
                        bin.withUnsafeMutableBufferPointer { bo in
                            num.withUnsafeMutableBufferPointer { no in
                                vc_fingerprint(
                                    a.bindMemory(to: UInt8.self).baseAddress,
                                    b.bindMemory(to: UInt8.self).baseAddress,
                                    da.bindMemory(to: UInt8.self).baseAddress, da.count,
                                    db.bindMemory(to: UInt8.self).baseAddress, db.count,
                                    bo.baseAddress,
                                    no.baseAddress, &nlen
                                )
                            }
                        }
                    }
                }
            }
        }
        guard rc == 0 else {
            throw VoiceChatCryptoError.native(VcErrorCode(rawValue: rc) ?? .internalError)
        }
        let numeric = String(bytes: num.prefix(nlen), encoding: .ascii) ?? ""
        return (Data(bin), numeric)
    }
}
