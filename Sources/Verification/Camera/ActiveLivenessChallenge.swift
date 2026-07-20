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
enum LivenessAction: String, CaseIterable {
    case turnLeft, turnRight, nod, blink

    var prompt: String {
        switch self {
        case .turnLeft:  return "Поверни голову ЛІВОРУЧ"
        case .turnRight: return "Поверни голову ПРАВОРУЧ"
        case .nod:       return "Кивни (підборіддя вниз)"
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

    // Пороги (радіани / частки) — ПОПЕРЕДНІ, калібрувати виміром.
    private let yawActionThreshold: Double = 0.35     // ~20° поворот
    private let pitchNodThreshold: Double = 0.25      // ~14° нахил вниз
    private let neutralYaw: Double = 0.12
    private let neutralPitch: Double = 0.12
    private let earOpen: Double = 0.24
    private let earClosed: Double = 0.15
    private let neutralFramesNeeded = 3
    private let perActionTimeout: TimeInterval = 6.0

    private(set) var sequence: [LivenessAction]
    private(set) var state: ChallengeState = .idle
    private var neutralRun = 0
    private var actionStartedAt: Date?
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
            let h = SHA256.hash(data: input)
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
        blinkArmed = false
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

    /// Обробити один кадр з позою й EAR. Повертає true, якщо челендж
    /// завершено (passed). Викликач зупиняє камеру на passed/failed.
    @discardableResult
    func process(yaw: Double?, pitch: Double?, ear: Double?) -> Bool {
        guard let yaw, let pitch else { return false }

        switch state {
        case .awaitingNeutral(let step):
            let neutral = abs(yaw) < neutralYaw && abs(pitch) < neutralPitch
                && (ear ?? 1) > earOpen
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
            if satisfied(action: sequence[step], yaw: yaw, pitch: pitch, ear: ear) {
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

    private func satisfied(action: LivenessAction, yaw: Double, pitch: Double, ear: Double?) -> Bool {
        switch action {
        case .turnLeft:  return yaw >  yawActionThreshold
        case .turnRight: return yaw < -yawActionThreshold
        case .nod:       return pitch < -pitchNodThreshold   // підборіддя вниз
        case .blink:
            // кліп = спершу відкриті (arm), потім закрилися
            guard let ear else { return false }
            if ear > earOpen { blinkArmed = true }
            if blinkArmed && ear < earClosed { return true }
            return false
        }
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
