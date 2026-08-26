import Foundation
import Security

enum Persistence {
    private static var applicationSupport: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let folder = base.appendingPathComponent("FlowGet", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder
    }

    static func load<T: Decodable>(_ type: T.Type, name: String, fallback: T) -> T {
        let url = applicationSupport.appendingPathComponent(name)
        guard let data = try? Data(contentsOf: url), let value = try? JSONDecoder.flowGet.decode(type, from: data) else { return fallback }
        return value
    }

    static func save<T: Encodable>(_ value: T, name: String) {
        let url = applicationSupport.appendingPathComponent(name)
        guard let data = try? JSONEncoder.flowGet.encode(value) else { return }
        try? data.write(to: url, options: [.atomic, .completeFileProtection])
    }
}
extension JSONEncoder {
    static var flowGet: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}

extension JSONDecoder {
    static var flowGet: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

enum KeychainStore {
    private static let service = "com.flowget.ios.session"

    static func save<T: Encodable>(_ value: T, account: String) {
        guard let data = try? JSONEncoder.flowGet.encode(value) else { return }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account]
        SecItemDelete(query as CFDictionary)
        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }

    static func load<T: Decodable>(_ type: T.Type, account: String) -> T? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account,
                                    kSecReturnData as String: true,
                                    kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return try? JSONDecoder.flowGet.decode(type, from: data)
    }

    static func delete(account: String) {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword,
                       kSecAttrService as String: service,
                       kSecAttrAccount as String: account] as CFDictionary)
    }
}
