import Foundation

/// Окремі типи для КОЖНОЇ гарантії (аудит F5): спільний enum
/// дозволяв безглузді комбінації (`liveness: .passed`). Тепер тип
/// кодує саме ту політику, яку заявляє: liveness = лише TrueDepth,
/// faceMatch = лише «збіглось». Невалідну комбінацію не скомпілювати.
enum LivenessEvidence: String {
    case trueDepthV1 = "depth"
    case activeChallengeV1 = "active"   // challenge-response (measured PAD)
}
enum FaceMatchEvidence: String { case passed }

/// Непідробний-на-рівні-типу доказ активної liveness: створюється ЛИШЕ
/// ChallengeLivenessManager після пройденого challenge-response.
struct ActiveLivenessProof {
    let mode: LivenessEvidence
    fileprivate init() { self.mode = .activeChallengeV1 }
    static func makeVerified() -> ActiveLivenessProof { ActiveLivenessProof() }
}

/// Непідробний-на-рівні-типу доказ живої присутності: створюється
/// ЛИШЕ FaceLivenessManager після реальної depth-перевірки (F7).
/// Немає публічного ініціалізатора зі «звичайним» прапорцем.
struct DepthLivenessProof {
    let mode: LivenessEvidence
    fileprivate init() { self.mode = .trueDepthV1 }
    /// Єдина фабрика — викликається лише з менеджера камери після
    /// підтвердженої обʼємності обличчя.
    static func makeVerified() -> DepthLivenessProof { DepthLivenessProof() }
}

struct VerificationEvidence {
    var method = "nfc_passport"
    /// ЄДИНИЙ рівень: TrueDepth підтвердив обʼємність обличчя. Без
    /// нього флоу зупиняється ще на клієнті (E-406).
    let liveness: LivenessEvidence
    let faceMatch: FaceMatchEvidence
    /// Активна liveness (challenge-response): id серверного nonce, з
    /// якого виведено послідовність дій — анти-реплей. Сервер звіряє,
    /// що челендж було видано цьому користувачу й свіжий.
    var activeLivenessChallengeId: String?
    var faceModel: String                                // лише "coreml" у release
    /// EF.SOD з чипа (base64 DER). Містить лише хеші DG, сертифікат
    /// і підпис — жодного персонального поля документа.
    var sodBase64: String?
    /// Хеші прочитаних груп даних: "dg1"/"dg2" → алгоритм → hex.
    var dgHashes: [String: [String: String]] = [:]
    var protocolVersion = 4

    /// Створюється лише з типізованих доказів етапів — сирі рядки
    /// сюди не потрапляють.
    init(livenessProof: DepthLivenessProof,
         faceMatch: FaceMatchEvidence,
         faceModel: String,
         activeLivenessChallengeId: String?,
         sodBase64: String?,
         dgHashes: [String: [String: String]]) {
        self.liveness = livenessProof.mode
        self.faceMatch = faceMatch
        self.faceModel = faceModel
        self.activeLivenessChallengeId = activeLivenessChallengeId
        self.sodBase64 = sodBase64
        self.dgHashes = dgHashes
    }

    /// Об'єднаний флоу: liveness доведено challenge-response (активна),
    /// а не depth. Ключова гарантія — саме активна liveness.
    init(activeProof: ActiveLivenessProof,
         faceMatch: FaceMatchEvidence,
         faceModel: String,
         activeLivenessChallengeId: String?,
         sodBase64: String?,
         dgHashes: [String: [String: String]]) {
        self.liveness = activeProof.mode
        self.faceMatch = faceMatch
        self.faceModel = faceModel
        self.activeLivenessChallengeId = activeLivenessChallengeId
        self.sodBase64 = sodBase64
        self.dgHashes = dgHashes
    }
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
            "activeLiveness": "passed",
            "activeLivenessChallengeId": evidence.activeLivenessChallengeId ?? "",
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
        // Defense-in-depth (аудит F6): клієнт вимагає той самий інваріант,
        // що обіцяє сервер — рівень strong і пройдену Passive Authentication.
        // Захищає від випадкового downgrade сервера чи проксі.
        guard (json["level"] as? String) == "strong",
              (json["passiveAuthentication"] as? String) == "passed" else {
            throw APIError.server(trs("Верифікацію не підтверджено на найвищому рівні. Спробуй ще раз."))
        }

        return true
    }
}
