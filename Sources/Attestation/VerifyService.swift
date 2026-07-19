import Foundation

/// Докази перевірки, що застосунок ЧЕСНО повідомляє серверу.
/// Значення — enum, а не «все пройдено»: сервер бачить, що саме
/// виконано, і вирішує, який рівень довіри видати.
///
/// Passive Authentication робить СЕРВЕР: клієнт передає SOD (підписаний
/// державою обʼєкт з хешами груп даних — БЕЗ імені/номера/фото) і хеші
/// DG1/DG2, які реально прочитав. Сервер перевіряє підпис за CSCA
/// України і збіг хешів. Тут клієнту на слово не вірять.
struct VerificationEvidence {
    enum Outcome: String { case passed, failed, heuristic }

    var method = "nfc_passport"
    var liveness: Outcome = .heuristic                   // TODO: real PAD
    var faceMatch: Outcome
    var faceModel: String                                // "coreml" | "vision_fallback"
    /// EF.SOD з чипа (base64 DER). Містить лише хеші DG, сертифікат
    /// і підпис — жодного персонального поля документа.
    var sodBase64: String?
    /// Хеші прочитаних груп даних: "dg1"/"dg2" → алгоритм → hex.
    /// Кілька алгоритмів — бо сервер порівнює тим, що вказаний у SOD.
    var dgHashes: [String: [String: String]] = [:]
    var protocolVersion = 3
}

enum VerifyService {
    /// POST /auth/verify/approve. Тіло — канонічний payload, ПІДПИСАНИЙ
    /// App Attest assertion (див. AppAttestService: hash = challenge ‖ payload).
    /// Дані документа НЕ передаються — лише результати перевірок (enum).
    /// Сервер зобовʼязаний: перевірити assertion над тим самим digest,
    /// assertion counter (replay), TTL/одноразовість challenge, і
    /// whitelist значень. Verified ID вищого рівня — лише коли
    /// passiveAuthentication == passed.
    @discardableResult
    static func approve(evidence: VerificationEvidence) async throws -> Bool {
        guard let token = AuthStore.token else { throw APIError.notLoggedIn }

        var body: [String: Any] = [
            "method": evidence.method,
            "liveness": evidence.liveness.rawValue,
            "faceMatch": evidence.faceMatch.rawValue,
            "faceModel": evidence.faceModel,
            "protocolVersion": evidence.protocolVersion,
            "endpoint": "/auth/verify/approve"
        ]
        // SOD + хеші DG — для серверної Passive Authentication.
        // Assertion підписує і їх: підмінити SOD після підпису неможливо.
        if let sod = evidence.sodBase64 {
            body["sod"] = sod
            body["dgHashes"] = evidence.dgHashes
        }

        // Assertion привʼязаний саме до цих байтів payload
        let attest = try await AppAttestService.assertionHeaders(for: body)

        var request = URLRequest(url: OstrovAPI.base.appendingPathComponent("auth/verify/approve"))
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        for (key, value) in attest.headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        // Дослівно ті ж байти, що підписані assertion
        request.httpBody = Data(attest.canonicalPayload.utf8)

        let (data, response) = try await URLSession.shared.data(for: request)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]

        guard code == 200, (json["verified"] as? Bool) == true else {
            throw APIError.server((json["error"] as? String) ?? "Не вдалося підтвердити статус у базі.")
        }

        return true
    }
}
