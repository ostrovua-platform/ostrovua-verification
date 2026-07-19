import Foundation
import CryptoKit
#if canImport(DeviceCheck)
import DeviceCheck
#endif

// ═══════════════════════════════════════════════════════════════════
//  Apple App Attest — доказ, що запит іде зі справжнього OstrovUA
//  на справжньому iPhone, а не зі скрипта чи зламаного клієнта.
//
//  Без цього сервер відхиляє /auth/verify/approve з 403
//  ("Device attestation required") — саме так і має бути:
//  статус Verified ID неможливо отримати в обхід застосунку.
//
//  Протокол (backend/auth/server.js + appattest.js):
//    1) POST /auth/verify/challenge            → {challengeId, challenge}
//    2) POST /auth/verify/attest-key           → реєстрація ключа пристрою
//       body {challengeId, keyId, attestation}
//    3) POST /auth/verify/approve
//       headers x-app-attest: <assertion b64>, x-attest-key: <keyId>
//       body    {method, challengeId}
//
//  clientDataHash = SHA256(challenge) — рівно так рахує сервер.
// ═══════════════════════════════════════════════════════════════════

enum AppAttestError: LocalizedError {
    case unsupported
    case keyGeneration(String)
    case attestationRejected(String)

    var errorDescription: String? {
        switch self {
        case .unsupported:
            return trs("Пристрій не підтримує App Attest — верифікація недоступна.")
        case .keyGeneration(let m):
            return m
        case .attestationRejected(let m):
            return m
        }
    }
}

enum AppAttestService {
    /// keyId зберігається на пристрої й прив'язаний до акаунта:
    /// у чужому акаунті ключ не спрацює (сервер звіряє contributor_id).
    private static var keyIdKey: String {
        "ostrov.attestKeyId." + (AuthStore.contributorId ?? "anon")
    }

    private static var storedKeyId: String? {
        get { UserDefaults.standard.string(forKey: keyIdKey) }
        set { UserDefaults.standard.set(newValue, forKey: keyIdKey) }
    }

    static var isSupported: Bool {
        #if canImport(DeviceCheck) && !targetEnvironment(simulator)
        return DCAppAttestService.shared.isSupported
        #else
        return false
        #endif
    }

    /// Готує заголовки для захищеного запиту.
    /// Повертає (headers, challengeId) — challengeId треба покласти в тіло.
    static func assertionHeaders(for body: [String: Any]) async throws -> (headers: [String: String], challengeId: String) {
        #if canImport(DeviceCheck) && !targetEnvironment(simulator)
        guard DCAppAttestService.shared.isSupported else { throw AppAttestError.unsupported }

        let service = DCAppAttestService.shared

        // Ключ пристрою: створюємо один раз і реєструємо на сервері
        let keyId: String
        if let existing = storedKeyId {
            keyId = existing
        } else {
            keyId = try await registerNewKey(service: service)
        }

        // Свіжий одноразовий челендж під саме цей запит
        let (challengeId, challenge) = try await requestChallenge()

        do {
            let assertion = try await service.generateAssertion(
                keyId,
                clientDataHash: Data(SHA256.hash(data: challenge))
            )

            return (
                headers: [
                    "x-app-attest": assertion.base64EncodedString(),
                    "x-attest-key": keyId
                ],
                challengeId: challengeId
            )
        } catch {
            // Ключ міг стати недійсним (перевстановлення, зміна акаунта) —
            // пробуємо один раз перереєструвати
            storedKeyId = nil
            let freshKeyId = try await registerNewKey(service: service)
            let (newChallengeId, newChallenge) = try await requestChallenge()
            let assertion = try await service.generateAssertion(
                freshKeyId,
                clientDataHash: Data(SHA256.hash(data: newChallenge))
            )
            return (
                headers: [
                    "x-app-attest": assertion.base64EncodedString(),
                    "x-attest-key": freshKeyId
                ],
                challengeId: newChallengeId
            )
        }
        #else
        throw AppAttestError.unsupported
        #endif
    }

    // MARK: - Кроки протоколу

    private static func requestChallenge() async throws -> (id: String, bytes: Data) {
        guard let token = AuthStore.token else { throw APIError.notLoggedIn }

        var request = URLRequest(url: OstrovAPI.base.appendingPathComponent("auth/verify/challenge"))
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (data, response) = try await URLSession.shared.data(for: request)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]

        guard code == 200,
              let id = json["challengeId"] as? String,
              let challengeB64 = json["challenge"] as? String,
              let bytes = Data(base64Encoded: challengeB64)
        else {
            throw APIError.server((json["error"] as? String) ?? trs("Сервер не видав челендж."))
        }

        return (id, bytes)
    }

    #if canImport(DeviceCheck) && !targetEnvironment(simulator)
    private static func registerNewKey(service: DCAppAttestService) async throws -> String {
        let keyId = try await service.generateKey()
        let (challengeId, challenge) = try await requestChallenge()

        let attestation = try await service.attestKey(
            keyId,
            clientDataHash: Data(SHA256.hash(data: challenge))
        )

        guard let token = AuthStore.token else { throw APIError.notLoggedIn }

        var request = URLRequest(url: OstrovAPI.base.appendingPathComponent("auth/verify/attest-key"))
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "challengeId": challengeId,
            "keyId": keyId,
            "attestation": attestation.base64EncodedString()
        ])

        let (data, response) = try await URLSession.shared.data(for: request)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]

        guard code == 200, (json["ok"] as? Bool) == true else {
            throw AppAttestError.attestationRejected(
                (json["error"] as? String) ?? trs("Сервер відхилив атестацію пристрою.")
            )
        }

        storedKeyId = keyId
        return keyId
    }
    #endif
}
