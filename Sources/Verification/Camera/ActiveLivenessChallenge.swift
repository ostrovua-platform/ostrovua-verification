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

    // Пороги ВІДНОСНО КАЛІБРОВАНОЇ БАЗИ користувача (аудит: 9/10 фейлів
    // живого — бо «прямо» ≠ horiz 0 при зйомці з рук). Спершу ловимо
    // нейтральне положення носа й відкритий EAR цієї людини, далі
    // повороти/кліпання міряємо як ВІДХИЛЕННЯ від бази.
    private let turnDelta: Double = 0.14        // відхилення носа для повороту
    private let neutralMargin: Double = 0.09    // «повернувся в нейтраль»
    private let blinkRatio: Double = 0.62       // око «закрите», якщо ear < ratio*base
    private let armRatio: Double = 0.80         // «відкрите» для arm
    private let neutralFramesNeeded = 3
    private let perActionTimeout: TimeInterval = 8.0

    private(set) var sequence: [LivenessAction]
    private(set) var state: ChallengeState = .idle
    private var neutralRun = 0
    private var actionStartedAt: Date?
    private var attemptStartedAt: Date?
    private var blinkArmed = false

    // Лічильник НЕВІРНИХ рухів (анти-реплей): заздалегідь записане відео
    // зі «всіма діями» неминуче показує не ту дію, поки челендж чекає
    // потрібну. Живий, що дивиться підказку, так майже не помиляється.
    private var wrongMoves = 0
    private var lastWrongCounted: LivenessAction?
    private let maxWrongMoves = 2        // 2-й великий невірний рух → фейл

    // Калібрування бази під конкретного користувача.
    private var baseHoriz: Double?
    private var baseEar: Double?
    private var calHoriz: [Double] = []
    private var calEar: [Double] = []
    private let calibrationSamples = 8

    /// Детермінована послідовність з серверного nonce (анти-реплей):
    /// однакова на клієнті й сервері, але непередбачувана наперед.
    /// seed = challenge bytes від сервера; length = скільки дій.
    init(seed: Data, length: Int = 2) {
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
        wrongMoves = 0
        lastWrongCounted = nil
        baseHoriz = nil; baseEar = nil
        calHoriz = []; calEar = []
    }

    private var calibrated: Bool { baseHoriz != nil && baseEar != nil }

    /// Загальний дедлайн попитки — щоб не зависати, якщо нейтраль так і
    /// не досягнута (напр., атака ніколи не центрується).
    private var overallDeadline: TimeInterval {
        perActionTimeout * Double(sequence.count) + 6.0
    }

    /// Поточна підказка користувачу.
    var guidance: String {
        if calibrated == false { return "Тримай обличчя прямо…" }
        switch state {
        case .awaitingNeutral: return "Дивись прямо в камеру"
        case .awaitingAction(let step): return sequence[step].prompt
        case .passed: return "Готово"
        case .failed(let m): return m
        case .idle: return ""
        }
    }

    /// Обробити кадр: horiz = зсув носа відносно лінії очей, ear.
    @discardableResult
    func process(horiz: Double?, ear: Double?) -> Bool {
        if case .awaitingNeutral = state {} else if case .awaitingAction = state {} else {
            return state == .passed
        }
        if let s = attemptStartedAt, Date().timeIntervalSince(s) > overallDeadline {
            state = .failed("Час вичерпано. Спробуй ще раз.")
            return false
        }
        guard let horiz else { return false }

        // ── Калібрування бази під користувача (перші кадри) ──────────
        if calibrated == false {
            calHoriz.append(horiz)
            if let e = ear { calEar.append(e) }
            if calHoriz.count >= calibrationSamples {
                baseHoriz = median(calHoriz)
                baseEar = calEar.isEmpty ? 0.30 : median(calEar)
                // дедлайн рахуємо від завершення калібрування
                attemptStartedAt = Date()
            }
            return false
        }
        let base = baseHoriz ?? 0
        let dev = horiz - base                    // відхилення від «прямо» цієї людини

        switch state {
        case .awaitingNeutral(let step):
            let neutral = abs(dev) < neutralMargin && eyesOpen(ear)
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
            let required = sequence[step]
            if satisfied(action: required, dev: dev, ear: ear) {
                let next = step + 1
                if next >= sequence.count { state = .passed; return true }
                neutralRun = 0
                state = .awaitingNeutral(step: next)
            } else if let ev = evidentAction(dev: dev, ear: ear), ev != required {
                // НЕВІРНИЙ рух: не та дія, поки ми чекаємо потрібну.
                // Записане наперед відео зі всіма діями неминуче сюди
                // потрапляє; живий, що читає підказку, — майже ні.
                if ev != lastWrongCounted {
                    lastWrongCounted = ev
                    wrongMoves += 1
                    if wrongMoves >= maxWrongMoves {
                        state = .failed("Забагато невірних рухів. Виконуй саме те, що на підказці.")
                        return false
                    }
                }
            } else if abs(dev) < neutralMargin {
                lastWrongCounted = nil        // повернувся в нейтраль → рахуємо наступний невірний
            }

        case .passed, .failed, .idle:
            break
        }
        return state == .passed
    }

    private func eyesOpen(_ ear: Double?) -> Bool {
        guard let ear, let base = baseEar, base > 0 else { return true }
        return ear > armRatio * base
    }

    /// Яка дія «очевидна» в цьому кадрі — для лічильника невірних рухів.
    /// blink тут спрощено (просто закрите око), цього досить, щоб зловити
    /// «моргання/поворот не в ту сторону, коли просили інше».
    private func evidentAction(dev: Double, ear: Double?) -> LivenessAction? {
        if dev < -turnDelta { return .turnLeft }
        if dev >  turnDelta { return .turnRight }
        if let ear, let b = baseEar, b > 0, ear < blinkRatio * b { return .blink }
        return nil
    }

    private func satisfied(action: LivenessAction, dev: Double, ear: Double?) -> Bool {
        switch action {
        // Знаки за виміром (дзеркало фронталки): ЛІВОРУЧ → −dev, ПРАВОРУЧ → +dev.
        case .turnLeft:  return dev < -turnDelta
        case .turnRight: return dev >  turnDelta
        case .blink:
            guard let ear, let base = baseEar, base > 0 else { return false }
            if ear > armRatio * base { blinkArmed = true }            // відкриті → arm
            if blinkArmed && ear < blinkRatio * base { return true }  // закрились → кліп
            return false
        }
    }

    private func median(_ a: [Double]) -> Double {
        let s = a.sorted(); let n = s.count
        return n == 0 ? 0 : (n % 2 == 1 ? s[n/2] : (s[n/2 - 1] + s[n/2]) / 2)
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
