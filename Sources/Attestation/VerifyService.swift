import Foundation

/// Докази перевірки, що застосунок ЧЕСНО повідомляє серверу.
/// Значення — enum, а не «все пройдено»: сервер бачить, що саме
/// виконано (наприклад, passiveAuthentication ще НЕ реалізовано),
/// і вирішує, який рівень довіри видати.
struct VerificationEvidence {
    enum Outcome: String { case passed, failed, notPerformed = "not_performed", heuristic }

    var method = "nfc_passport"
    var passiveAuthentication: Outcome = .notPerformed   // TODO: server-side CSCA
    var liveness: Outcome = .heuristic                   // TODO: real PAD
    var faceMatch: Outcome
    var faceModel: String                                // "coreml" | "vision_fallback"
    var protocolVersion = 2
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

        let body: [String: Any] = [
            "method": evidence.method,
            "passiveAuthentication": evidence.passiveAuthentication.rawValue,
            "liveness": evidence.liveness.rawValue,
            "faceMatch": evidence.faceMatch.rawValue,
            "faceModel": evidence.faceModel,
            "protocolVersion": evidence.protocolVersion,
            "endpoint": "/auth/verify/approve"
        ]

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
