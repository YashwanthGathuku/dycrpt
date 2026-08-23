import Foundation
import Security

/// iOS host-side key lifecycle for dycrpt `EncryptedFileStorage`.
///
/// The 32-byte data key is stored as a device-only Keychain generic-password
/// item. `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` keeps it available
/// to normal background messaging after the first unlock while preventing it
/// from migrating through backups to another device. The raw key must exist in
/// memory only long enough to initialize the Rust storage backend.
final class VoiceChatStorageKey {
    enum StorageKeyError: Error {
        case keychain(OSStatus)
        case random(OSStatus)
        case invalidLength
    }

    private let service = "com.voicechat.crypto.dycrpt.storage"
    private let account = "dycrpt-storage-key-v1"
    private let keyLength = 32

    func loadOrCreate() throws -> Data {
        if let existing = try load() {
            guard existing.count == keyLength else {
                throw StorageKeyError.invalidLength
            }
            return existing
        }

        var bytes = [UInt8](repeating: 0, count: keyLength)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
            throw StorageKeyError.random(status)
        }

        let data = Data(bytes)
        bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
        do {
            try store(data)
            return data
        } catch {
            // Data is value-semantic and may have copies; callers should keep
            // its lifetime short and hand it directly to the Rust initializer.
            throw error
        }
    }

    func destroy() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw StorageKeyError.keychain(status)
        }
    }

    private func load() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = item as? Data else {
            throw StorageKeyError.keychain(status)
        }
        return data
    }

    private func store(_ data: Data) throws {
        guard data.count == keyLength else {
            throw StorageKeyError.invalidLength
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: data,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            // Another process/scene may have raced creation. Never overwrite an
            // existing key because doing so would orphan the encrypted store.
            guard let existing = try load(), existing.count == keyLength else {
                throw StorageKeyError.invalidLength
            }
            return
        }
        guard status == errSecSuccess else {
            throw StorageKeyError.keychain(status)
        }
    }
}
