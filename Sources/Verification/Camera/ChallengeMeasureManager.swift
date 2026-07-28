import Foundation
import AVFoundation
import Vision
import Combine

/// Менеджер вимірювання активної liveness (аудит #8). ОКРЕМА
/// фронтальна камера + VNDetectFaceLandmarksRequest (поза yaw/pitch +
/// очі для EAR). Production-флоу FaceLivenessManager НЕ чіпає — спершу
/// міряємо челендж стендом, потім вирішуємо про інтеграцію.
///
/// Одна «попитка» = одна випадкова послідовність дій. Оператор ставить
/// мітку (bonafide/photo/screen) і намагається пройти челендж живим
/// обличчям або атакою; телеметрія → ChallengeLogger → challenge_score.py.
final class ChallengeMeasureManager: NSObject, ObservableObject {
    @Published private(set) var guidance: String = "Натисни «Нова попитка»"
    @Published private(set) var passedText: String = ""

    let session = AVCaptureSession()
    private let output = AVCaptureVideoDataOutput()
    private let queue = DispatchQueue(label: "ostrovua.challenge.measure")
    private var challenge: ActiveLivenessChallenge?
    private var running = false

    func startSession() {
        queue.async {
            guard self.session.inputs.isEmpty else { self.session.startRunning(); return }
            self.session.beginConfiguration()
            self.session.sessionPreset = .medium
            guard let dev = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .front),
                  let input = try? AVCaptureDeviceInput(device: dev),
                  self.session.canAddInput(input) else {
                DispatchQueue.main.async { self.guidance = "Камера недоступна" }; return
            }
            self.session.addInput(input)
            self.output.setSampleBufferDelegate(self, queue: self.queue)
            // 420 bi-planar → площина 0 = Y (яскравість) для ScreenArtifactDetector.
            self.output.videoSettings = [
                String(kCVPixelBufferPixelFormatTypeKey): kCVPixelFormatType_420YpCbCr8BiPlanarFullRange
            ]
            if self.session.canAddOutput(self.output) { self.session.addOutput(self.output) }
            self.session.commitConfiguration()
            self.session.startRunning()
        }
    }

    func stopSession() { queue.async { self.session.stopRunning() } }

    /// Нова попитка: генеруємо випадкову послідовність (тут — локальний
    /// seed; у проді seed = серверний challenge для анти-реплею).
    func newAttempt() {
        var seed = Data(count: 16)
        _ = seed.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        let c = ActiveLivenessChallenge(seed: seed, length: 2)
        c.start()
        challenge = c
        running = true
        DispatchQueue.main.async {
            self.passedText = ""
            self.guidance = "Послідовність: " + c.sequence.map { $0.rawValue }.joined(separator: " → ")
        }
    }
}

extension ChallengeMeasureManager: AVCaptureVideoDataOutputSampleBufferDelegate {
    func captureOutput(_ o: AVCaptureOutput, didOutput sb: CMSampleBuffer, from c: AVCaptureConnection) {
        guard running, let challenge, let pb = CMSampleBufferGetImageBuffer(sb) else { return }

        let req = VNDetectFaceLandmarksRequest { [weak self] req, _ in
            guard let self else { return }
            guard let face = (req.results as? [VNFaceObservation])?.first else {
                // Немає обличчя — все одно рухаємо таймаут попитки.
                if challenge.process(horiz: nil, ear: nil) == false,
                   case .failed = challenge.state {
                    self.running = false
                    ChallengeLogger.shared.attemptFinished(passed: false)
                    DispatchQueue.main.async { self.passedText = "✗ не пройдено" }
                }
                return
            }
            let lm = face.landmarks
            // Позу рахуємо з геометрії лендмарок (Vision yaw/pitch грубі/nil).
            let horiz = ActiveLivenessChallenge.horizontalNoseOffset(
                nose: lm?.nose, leftEye: lm?.leftEye, rightEye: lm?.rightEye)
            let earL = ActiveLivenessChallenge.eyeAspectRatio(lm?.leftEye)
            let earR = ActiveLivenessChallenge.eyeAspectRatio(lm?.rightEye)
            let ear: Double? = {
                switch (earL, earR) {
                case let (l?, r?): return (l + r) / 2
                case let (l?, nil): return l
                case let (nil, r?): return r
                default: return nil
                }
            }()

            // Ознаки екрана (муар/висока частота + глар) — вимірюваний
            // сигнал анти-реплею; пишемо поруч, скоринг оцінить розділення.
            let art = ScreenArtifactDetector.analyze(pb, faceBox: face.boundingBox)
            // У колонку yaw пишемо horiz (для калібрування), pitch не використовуємо.
            ChallengeLogger.shared.frame(state: self.stateName(challenge.state),
                                         yaw: horiz, pitch: nil, ear: ear,
                                         glare: art.glareFraction, hf: art.hfEnergy)

            let done = challenge.process(horiz: horiz, ear: ear)
            DispatchQueue.main.async { self.guidance = challenge.guidance }

            if done {
                self.running = false
                ChallengeLogger.shared.attemptFinished(passed: true)
                DispatchQueue.main.async { self.passedText = "✓ ПРОЙДЕНО" }
            } else if case .failed = challenge.state {
                self.running = false
                ChallengeLogger.shared.attemptFinished(passed: false)
                DispatchQueue.main.async { self.passedText = "✗ не пройдено" }
            }
        }
        try? VNImageRequestHandler(cvPixelBuffer: pb, orientation: .leftMirrored, options: [:]).perform([req])
    }

    private func stateName(_ s: ChallengeState) -> String {
        switch s {
        case .idle: return "idle"
        case .awaitingNeutral(let i): return "neutral\(i)"
        case .awaitingAction(let i): return "action\(i)"
        case .passed: return "passed"
        case .failed: return "failed"
        }
    }
}
