import Foundation

// MARK: - Step 1: /fingerprint/init

struct InitRequestBody: Encodable {
    let appId: String
    let bundleId: String
    let tempId: String
    let timestamp: Int64
}

struct InitResponseBody: Decodable {
    let nonce: String
    let sessionToken: String
    let rsaPublicKey: String
    let serverTimestamp: Int64
}

// MARK: - Step 4: /fingerprint/generate

struct GenerateRequestBody: Encodable {
    let tempId: String
    let nonce: String
    let encryptedAesKey: String
    let encryptedData: String
    let timestamp: Int64
    let signature: String
}

struct GenerateResponseBody: Decodable {
    let deviceId: String
    let success: Bool
}

// MARK: - Endpoints

enum Endpoint {
    static let initialize = "fingerprint/init"
    static let generate = "fingerprint/generate"
}
