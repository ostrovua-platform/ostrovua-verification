import Foundation

// MARK: - Верификация: подтверждение статуса в базе

enum VerifyService {
    /// POST /auth/verify/approve — сервер ставит contributors.verified = true
    /// для текущего пользователя (по JWT). Данные документа НЕ передаются —
    /// только факт успешной проверки на устройстве.
    @discardableResult
    static func approve(method: String = "nfc_passport") async throws -> Bool {
        guard let token = AuthStore.token else { throw APIError.notLoggedIn }

        // Сервер приймає підтвердження ЛИШЕ з атестованого пристрою
        // (App Attest). Без цього — 403: обійти застосунок неможливо.
        let attest = try await AppAttestService.assertionHeaders(for: ["method": method])

        var request = URLRequest(url: OstrovAPI.base.appendingPathComponent("auth/verify/approve"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        for (key, value) in attest.headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "method": method,
            "challengeId": attest.challengeId
        ])

        let (data, response) = try await URLSession.shared.data(for: request)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]

        guard code == 200, (json["verified"] as? Bool) == true else {
            throw APIError.server((json["error"] as? String) ?? "Не вдалося підтвердити статус у базі.")
        }

        return true
    }
}
