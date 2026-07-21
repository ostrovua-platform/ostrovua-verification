import Foundation
import Vision
import CoreGraphics
import CryptoKit

/// Активна liveness — challenge-response (аудит #8, реальний anti-spoofing).
///
/// Ідея: після захоплення стабільного обличчя користувач має виконати
/// ВИПАДКОВУ послідовність дій (поворот голови вліво/вправо, кивок,
/// кліпання), ПРИВʼЯЗАНУ до серверного nonce. Статичне фото не змінює
/// позу; заздалегідь записане відео не збігається з новою випадковою
/// послідовністю й порядком → атака не проходить.
///
/// Сигнали з Vision:
///  • yaw/pitch (радіани) — поворот/нахил голови;
///  • EAR (eye aspect ratio) з лендмарок очей — кліпання.
///
/// ⚠️ ПОРОГИ ПОПЕРЕДНІ — калібруються на пристрої через телеметрію
/// (ChallengeLogger + Tools/PADScore/challenge_score.py). Ми не
/// заявляємо готовність, доки вимір не підтвердить APCER→0, BPCER малий.
/// Дії. `nod` прибрано: Vision на пристроях повертає pitch=nil, тож
/// нахил ненадійний. Позу рахуємо з ГЕОМЕТРІЇ лендмарок (зсув носа
/// відносно лінії очей) — надійніше за грубий Vision-yaw (2 значення).
enum LivenessAction: String, CaseIterable {
    case turnLeft, turnRight, blink

    var prompt: String {
        switch self {
        case .turnLeft:  return "Поверни голову ЛІВОРУЧ"
        case .turnRight: return "Поверни голову ПРАВОРУЧ"
        case .blink:     return "Кліпни очима"
        }
    }
}

/// Стан проходження челенджу.
enum ChallengeState: Equatable {
    case idle
    case awaitingNeutral(step: Int)   // повернутися в нейтраль перед дією
    case awaitingAction(step: Int)    // виконати поточну дію
    case passed
    case failed(String)
}

final class ActiveLivenessChallenge {

    // Пороги — ПОПЕРЕДНІ, калібрувати виміром.
    // horiz = (нос.x − середина_очей.x) / міжочна_відстань. Фронтально
    // ≈ 0; поворот голови зсуває ніс → |horiz| росте.
    private let turnThreshold: Double = 0.18     // поворот зараховано
    private let neutralHoriz: Double = 0.10      // «дивиться прямо»
    private let earOpen: Double = 0.24
    private let earClosed: Double = 0.15
    private let neutralFramesNeeded = 3
    // 8 c: перший вимір показав фейл живого через таймаут на 3-й дії
    // (поріг брався легко, не встиг за 6 c). Атаку це не послаблює —
    // фото/екран не виконають дію взагалі.
    private let perActionTimeout: TimeInterval = 8.0

    private(set) var sequence: [LivenessAction]
    private(set) var state: ChallengeState = .idle
    private var neutralRun = 0
    private var actionStartedAt: Date?
    private var attemptStartedAt: Date?
    private var blinkArmed = false        // спершу очі відкриті, потім закриті → кліп

    /// Детермінована послідовність з серверного nonce (анти-реплей):
    /// однакова на клієнті й сервері, але непередбачувана наперед.
    /// seed = challenge bytes від сервера; length = скільки дій.
    init(seed: Data, length: Int = 3) {
        var actions: [LivenessAction] = []
        let all = LivenessAction.allCases
        // PRNG = послідовні блоки SHA256(seed ‖ counter)
        var counter: UInt8 = 0
        var last: LivenessAction?
        while actions.count < length {
            var input = seed; input.append(counter); counter &+= 1
            let h = Array(SHA256.hash(data: input))   // Digest → [UInt8]
            let byte = h.first ?? 0
            let pick = all[Int(byte) % all.count]
            if pick != last {           // без негайних повторів
                actions.append(pick); last = pick
            }
        }
        self.sequence = actions
    }

    func start() {
        state = .awaitingNeutral(step: 0)
        neutralRun = 0
        actionStartedAt = nil
        attemptStartedAt = Date()
        blinkArmed = false
    }

    /// Загальний дедлайн попитки — щоб не зависати, якщо нейтраль так і
    /// не досягнута (напр., атака ніколи не центрується).
    private var overallDeadline: TimeInterval {
        perActionTimeout * Double(sequence.count) + 6.0
    }

    /// Поточна підказка користувачу.
    var guidance: String {
        switch state {
        case .awaitingNeutral: return "Дивись прямо в камеру"
        case .awaitingAction(let step): return sequence[step].prompt
        case .passed: return "Готово"
        case .failed(let m): return m
        case .idle: return ""
        }
    }

    /// Обробити кадр: horiz = зсув носа відносно лінії очей, ear.
    /// Повертає true, якщо челендж завершено (passed).
    /// ЗНАК horiz для ліво/право може відрізнятись через дзеркало
    /// фронталки — калібрується виміром (якщо ліво/право переплутані,
    /// міняємо знаки нижче).
    @discardableResult
    func process(horiz: Double?, ear: Double?) -> Bool {
        // Загальний таймаут (працює навіть коли horiz nil / нема обличчя)
        if case .awaitingNeutral = state {} else if case .awaitingAction = state {} else {
            return state == .passed
        }
        if let s = attemptStartedAt, Date().timeIntervalSince(s) > overallDeadline {
            state = .failed("Час вичерпано. Спробуй ще раз.")
            return false
        }
        guard let horiz else { return false }

        switch state {
        case .awaitingNeutral(let step):
            let neutral = abs(horiz) < neutralHoriz && (ear ?? 1) > earOpen
            neutralRun = neutral ? neutralRun + 1 : 0
            if neutralRun >= neutralFramesNeeded {
                state = .awaitingAction(step: step)
                actionStartedAt = Date()
                blinkArmed = false
            }

        case .awaitingAction(let step):
            if let s = actionStartedAt, Date().timeIntervalSince(s) > perActionTimeout {
                state = .failed("Не встиг виконати дію. Спробуй ще раз.")
                return false
            }
            if satisfied(action: sequence[step], horiz: horiz, ear: ear) {
                let next = step + 1
                if next >= sequence.count {
                    state = .passed
                    return true
                } else {
                    neutralRun = 0
                    state = .awaitingNeutral(step: next)
                }
            }

        case .passed, .failed, .idle:
            break
        }
        return state == .passed
    }

    private func satisfied(action: LivenessAction, horiz: Double, ear: Double?) -> Bool {
        switch action {
        // Знаки скориговано за виміром (дзеркало фронталки): поворот
        // голови ЛІВОРУЧ зсуває ніс у −horiz, ПРАВОРУЧ — у +horiz.
        case .turnLeft:  return horiz < -turnThreshold
        case .turnRight: return horiz >  turnThreshold
        case .blink:
            guard let ear else { return false }
            if ear > earOpen { blinkArmed = true }          // спершу відкриті
            if blinkArmed && ear < earClosed { return true } // потім закрились
            return false
        }
    }

    // MARK: - Геометрія: горизонтальний зсув носа відносно очей

    /// horiz = (nose.x − eyeMid.x) / interEyeDistance. Точки — з лендмарок
    /// Vision (нормалізовані в bounding box обличчя).
    static func horizontalNoseOffset(nose: VNFaceLandmarkRegion2D?,
                                     leftEye: VNFaceLandmarkRegion2D?,
                                     rightEye: VNFaceLandmarkRegion2D?) -> Double? {
        func center(_ r: VNFaceLandmarkRegion2D?) -> CGPoint? {
            guard let pts = r?.normalizedPoints, pts.isEmpty == false else { return nil }
            let s = pts.reduce(CGPoint.zero) { CGPoint(x: $0.x + $1.x, y: $0.y + $1.y) }
            return CGPoint(x: s.x / CGFloat(pts.count), y: s.y / CGFloat(pts.count))
        }
        guard let n = center(nose), let l = center(leftEye), let r = center(rightEye) else { return nil }
        let eyeMidX = (l.x + r.x) / 2
        let inter = hypot(l.x - r.x, l.y - r.y)
        guard inter > 1e-6 else { return nil }
        return Double((n.x - eyeMidX) / inter)
    }

    // MARK: - EAR з лендмарок ока (статичне — використати у менеджері камери)

    /// Eye aspect ratio: висота/ширина ока за нормалізованими точками
    /// Vision. Низький EAR = око закрите.
    static func eyeAspectRatio(_ eye: VNFaceLandmarkRegion2D?) -> Double? {
        guard let pts = eye?.normalizedPoints, pts.count >= 4 else { return nil }
        let xs = pts.map { Double($0.x) }, ys = pts.map { Double($0.y) }
        let width = (xs.max()! - xs.min()!)
        let height = (ys.max()! - ys.min()!)
        guard width > 1e-6 else { return nil }
        return height / width
    }
}
