import Foundation
import Security

/// Rollback anchor for dycrpt on iOS.
///
/// ## Read this before shipping
///
/// iOS exposes no app-accessible hardware monotonic counter. The Secure Enclave
/// signs and wraps; it does not vend a counter that provably only increases.
///
/// ### What this defends against
///
/// **Backup/restore rollback.** The counter is a Keychain generic-password item
/// with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Items with a
/// `ThisDeviceOnly` protection class are excluded from iCloud backup and from
/// encrypted iTunes/Finder backups, and do not migrate to a new device.
///
/// So restoring an old app container, or moving to a new phone, leaves the
/// counter absent while the state file returns. That surfaces to Rust as
/// `VC_STATE_LOST` — terminal, fail-closed, correct.
///
/// ### What this does NOT defend against
///
/// **A jailbroken or otherwise compromised device.** An attacker with Keychain
/// access can capture the counter and state file together and replay both. The
/// pair stays internally consistent and the rollback is invisible here.
/// Defending against that requires an anchor the attacker does not hold — a
/// server-side counter. See `ServerRollbackAnchor`.
///
/// ### Ordering requirement
///
/// `commit` writes the counter with `kSecAttrAccessibleAfterFirstUnlock…`, so it
/// is unavailable before first unlock after boot. If your app performs crypto
/// from a background push before first unlock, `current()` will fail and the
/// engine will report `VC_ANCHOR_UNAVAILABLE`. That is a transient, retryable
/// condition and must NOT be treated as a rollback — the Rust layer already
/// gives you a distinct code for exactly this reason.
///
/// Thread-safety: guarded by a serial queue. The Rust engine is concurrent and
/// the C shim adds no locking.
public final class VoiceChatRollbackAnchor {

    public enum AnchorError: Error {
        case keychain(OSStatus)
        case corrupt
    }

    private let service = "com.voicechat.crypto.dycrpt.anchor"
    private let account = "dycrpt-anchor-v1"
    private let queue = DispatchQueue(label: "com.voicechat.crypto.dycrpt.anchor")

    public init() {}

    /// Committed anchor value; 0 for a never-provisioned device.
    public func current() throws -> UInt64 {
        try queue.sync {
            guard let data = try loadRaw() else { return 0 }
            guard data.count == 8 else { throw AnchorError.corrupt }
            return data.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self).littleEndian }
        }
    }

    /// Atomic move from `expected` to `expected + 1`. Returns the new value.
    /// Throws if the stored value is not `expected`; the durable value is never
    /// modified on a failure path.
    public func compareAndIncrement(expected: UInt64) throws -> UInt64 {
        try queue.sync {
            let observed: UInt64
            if let data = try loadRaw() {
                guard data.count == 8 else { throw AnchorError.corrupt }
                observed = data.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self).littleEndian }
            } else {
                observed = 0
            }
            guard observed == expected else { throw AnchorError.corrupt }

            let next = expected + 1
            var le = next.littleEndian
            let payload = Data(bytes: &le, count: 8)
            try store(payload, replacingExisting: observed != 0 || (try loadRaw()) != nil)
            return next
        }
    }

    /// Destroy the anchor. Only for deliberate, user-visible device reset.
    public func destroy() throws {
        try queue.sync {
            let q: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
            ]
            let status = SecItemDelete(q as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw AnchorError.keychain(status)
            }
        }
    }

    private func loadRaw() throws -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        switch status {
        case errSecSuccess:
            return out as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw AnchorError.keychain(status)
        }
    }

    private func store(_ data: Data, replacingExisting: Bool) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if replacingExisting {
            let status = SecItemUpdate(
                base as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            if status == errSecSuccess { return }
            if status != errSecItemNotFound { throw AnchorError.keychain(status) }
        }
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw AnchorError.keychain(status) }
    }
}

// MARK: - C bridge

/// Boxed context handed to the Rust engine as `VcRollbackAnchorCallbacks.ctx`.
///
/// Must outlive the engine handle. `VoiceChatPersistentEngine` owns it.
public final class AnchorBox {
    let anchor: VoiceChatRollbackAnchor
    init(_ a: VoiceChatRollbackAnchor) { self.anchor = a }
}

private func anchorCurrent(_ ctx: UnsafeMutableRawPointer?, _ out: UnsafeMutablePointer<UInt64>?)
    -> Int32
{
    guard let ctx, let out else { return 1 }
    let box = Unmanaged<AnchorBox>.fromOpaque(ctx).takeUnretainedValue()
    do {
        out.pointee = try box.anchor.current()
        return 0
    } catch {
        return 1
    }
}

private func anchorCas(
    _ ctx: UnsafeMutableRawPointer?, _ expected: UInt64, _ out: UnsafeMutablePointer<UInt64>?
) -> Int32 {
    guard let ctx, let out else { return 1 }
    let box = Unmanaged<AnchorBox>.fromOpaque(ctx).takeUnretainedValue()
    do {
        out.pointee = try box.anchor.compareAndIncrement(expected: expected)
        return 0
    } catch {
        return 1
    }
}

/// Opens the persistent Rust engine with Keychain-backed storage key and anchor.
///
/// The returned object owns the anchor box; releasing it while the engine handle
/// is alive would leave Rust holding a dangling `ctx`, which for a *rollback*
/// anchor means silently losing rollback detection rather than crashing.
public final class VoiceChatPersistentEngine {

    public enum OpenError: Error {
        /// Terminal. Stale state, or state lost. Do not retry, do not
        /// re-provision silently — see the header docs on recovery policy.
        case rollbackDetected
        case stateLost
        /// Transient. Anchor unreadable, e.g. before first unlock.
        case anchorUnavailable
        /// Device was never provisioned; call `provision` instead.
        case notInitialized
        case native(Int32)
    }

    public let handle: VcHandle
    private let box: AnchorBox

    public static func open(
        deviceId: Data, profile: UInt8, path: String, storageKey: Data,
        anchor: VoiceChatRollbackAnchor, createIfAbsent: Bool
    ) throws -> VoiceChatPersistentEngine {
        precondition(storageKey.count == 32, "storage key must be 32 bytes")
        let box = AnchorBox(anchor)
        let cbs = VcRollbackAnchorCallbacks(
            ctx: Unmanaged.passUnretained(box).toOpaque(),
            current: anchorCurrent,
            compare_and_increment: anchorCas
        )

        var handle: VcHandle = 0
        let pathBytes = Array(path.utf8)
        let rc: Int32 = deviceId.withUnsafeBytes { dev in
            storageKey.withUnsafeBytes { key in
                vc_engine_open_persistent(
                    dev.bindMemory(to: UInt8.self).baseAddress, deviceId.count,
                    profile,
                    pathBytes, pathBytes.count,
                    key.bindMemory(to: UInt8.self).baseAddress,
                    cbs,
                    createIfAbsent ? 1 : 0,
                    &handle,
                    nil
                )
            }
        }

        switch rc {
        case 0: return VoiceChatPersistentEngine(handle: handle, box: box)
        case 7: throw OpenError.rollbackDetected
        case 8: throw OpenError.stateLost
        case 9: throw OpenError.anchorUnavailable
        case 10: throw OpenError.notInitialized
        default: throw OpenError.native(rc)
        }
    }

    private init(handle: VcHandle, box: AnchorBox) {
        self.handle = handle
        self.box = box
    }

    deinit {
        _ = vc_engine_destroy(handle)
        // `box` is released only after the engine is destroyed, so no in-flight
        // native call can still reach through the raw ctx pointer.
    }
}
