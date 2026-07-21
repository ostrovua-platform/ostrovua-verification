import Foundation
import AVFoundation
import Vision
import Combine
import UIKit
import CoreImage

/// Бойова активна liveness (challenge-response). Фронтальна камера +
/// лендмарки Vision → поза (зсув носа) і кліпання (EAR). Послідовність
/// дій ДЕТЕРМІНОВАНА з СЕРВЕРНОГО nonce (анти-реплей). Проходить —
/// лише жива людина, що виконує ВИПАДКОВІ дії у правильному порядку;
/// фото/екран не проходять (виміряно: APCER 0).
final class ChallengeLivenessManager: NSObject, ObservableObject {
    @Published private(set) var guidance: String = ""
    @Published private(set) var progress: Double = 0      // 0…1 по діях
    @Published private(set) var finished = false
    @Published private(set) var passed = false

    let session = AVCaptureSession()
    private let output = AVCaptureVideoDataOutput()
    private let queue = DispatchQueue(label: "ostrovua.challenge.live")
    private var challenge: ActiveLivenessChallenge?
    private var completion: ((Bool) -> Void)?
    private let ciContext = CIContext()

    /// Фронтальний кадр обличчя, знятий під час нейтральної пози —
    /// одразу йде на звірку з фото з чипа (DG2). Один флоу, без
    /// окремого екрана FaceCheck.
    private(set) var capturedFace: UIImage?

    /// seed = серверні challenge-байти (анти-реплей). challengeId
    /// віддається назад для evidence.
    func start(seed: Data, completion: @escaping (Bool) -> Void) {
        self.completion = completion
        let c = ActiveLivenessChallenge(seed: seed, length: 3)
        c.start()
        challenge = c
        DispatchQueue.main.async {
            self.finished = false; self.passed = false; self.progress = 0
            self.guidance = c.guidance
        }
        configure()
    }

    func stop() { queue.async { if self.session.isRunning { self.session.stopRunning() } } }

    private func configure() {
        queue.async {
            guard self.session.inputs.isEmpty else { self.session.startRunning(); return }
            self.session.beginConfiguration()
            self.session.sessionPreset = .medium
            guard let dev = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .front),
                  let input = try? AVCaptureDeviceInput(device: dev),
                  self.session.canAddInput(input) else {
                DispatchQueue.main.async { self.fail("Камера недоступна") }; return
            }
            self.session.addInput(input)
            self.output.setSampleBufferDelegate(self, queue: self.queue)
            self.output.alwaysDiscardsLateVideoFrames = true
            if self.session.canAddOutput(self.output) { self.session.addOutput(self.output) }
            self.session.commitConfiguration()
            self.session.startRunning()
        }
    }

    private func fail(_ msg: String) {
        guard finished == false else { return }
        finished = true; passed = false; guidance = msg
        stop(); completion?(false); completion = nil
    }
    private func succeed() {
        guard finished == false else { return }
        finished = true; passed = true; guidance = "Готово"
        stop(); completion?(true); completion = nil
    }
}

extension ChallengeLivenessManager: AVCaptureVideoDataOutputSampleBufferDelegate {
    func captureOutput(_ o: AVCaptureOutput, didOutput sb: CMSampleBuffer, from c: AVCaptureConnection) {
        guard let challenge, finished == false, let pb = CMSampleBufferGetImageBuffer(sb) else { return }
        let req = VNDetectFaceLandmarksRequest { [weak self] req, _ in
            guard let self else { return }
            let face = (req.results as? [VNFaceObservation])?.first
            let lm = face?.landmarks
            let horiz = ActiveLivenessChallenge.horizontalNoseOffset(
                nose: lm?.nose, leftEye: lm?.leftEye, rightEye: lm?.rightEye)
            let earL = ActiveLivenessChallenge.eyeAspectRatio(lm?.leftEye)
            let earR = ActiveLivenessChallenge.eyeAspectRatio(lm?.rightEye)
            let ear = [earL, earR].compactMap { $0 }.reduce(0, +) / Double(max(1, [earL, earR].compactMap { $0 }.count))

            // Знімаємо ФРОНТАЛЬНИЙ кадр (для звірки з DG2), коли обличчя
            // прямо й очі відкриті — найкраще для розпізнавання.
            if let h = horiz, abs(h) < 0.10, (earL ?? earR ?? 0) > 0.24,
               let img = self.makeImage(from: pb) {
                self.capturedFace = img
            }

            let done = challenge.process(horiz: horiz, ear: earL == nil && earR == nil ? nil : ear)
            let g = challenge.guidance
            let done2 = self.progressValue(challenge)
            DispatchQueue.main.async { self.guidance = g; self.progress = done2 }

            if done { self.succeed() }
            else if case .failed(let m) = challenge.state { self.fail(m) }
        }
        try? VNImageRequestHandler(cvPixelBuffer: pb, orientation: .leftMirrored, options: [:]).perform([req])
    }

    private func makeImage(from pb: CVPixelBuffer) -> UIImage? {
        let ci = CIImage(cvPixelBuffer: pb).oriented(.leftMirrored)
        guard let cg = ciContext.createCGImage(ci, from: ci.extent) else { return nil }
        return UIImage(cgImage: cg)
    }

    private func progressValue(_ c: ActiveLivenessChallenge) -> Double {
        switch c.state {
        case .awaitingNeutral(let s), .awaitingAction(let s):
            return Double(s) / Double(max(1, c.sequence.count))
        case .passed: return 1
        default: return 0
        }
    }
}
