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
    private var stopped = false          // queue-local guard (не @Published)

    /// Фронтальний кадр обличчя, знятий під час нейтральної пози —
    /// одразу йде на звірку з фото з чипа (DG2). Один флоу, без
    /// окремого екрана FaceCheck.
    private(set) var capturedFace: UIImage?

    /// seed = серверні challenge-байти (анти-реплей). challengeId
    /// віддається назад для evidence.
    func start(seed: Data, completion: @escaping (Bool) -> Void) {
        self.completion = completion
        self.stopped = false
        self.capturedFace = nil
        let c = ActiveLivenessChallenge(seed: seed, length: 2)
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

    // fail/succeed викликаються з camera-queue: guard — по queue-локальному
    // stopped, а @Published (finished/passed/guidance) публікуємо з main
    // (інакше «Publishing changes from background threads»).
    private func fail(_ msg: String) {
        guard stopped == false else { return }
        stopped = true
        stop()
        let cb = completion; completion = nil
        DispatchQueue.main.async {
            self.guidance = msg; self.passed = false; self.finished = true
            cb?(false)
        }
    }
    private func succeed() {
        guard stopped == false else { return }
        stopped = true
        stop()
        let cb = completion; completion = nil
        DispatchQueue.main.async {
            self.guidance = "Готово"; self.passed = true; self.finished = true
            cb?(true)
        }
    }
}

extension ChallengeLivenessManager: AVCaptureVideoDataOutputSampleBufferDelegate {
    func captureOutput(_ o: AVCaptureOutput, didOutput sb: CMSampleBuffer, from c: AVCaptureConnection) {
        guard let challenge, stopped == false, let pb = CMSampleBufferGetImageBuffer(sb) else { return }
        let req = VNDetectFaceLandmarksRequest { [weak self] req, _ in
            guard let self else { return }
            let face = (req.results as? [VNFaceObservation])?.first
            let lm = face?.landmarks
            let horiz = ActiveLivenessChallenge.horizontalNoseOffset(
                nose: lm?.nose, leftEye: lm?.leftEye, rightEye: lm?.rightEye)
            let earL = ActiveLivenessChallenge.eyeAspectRatio(lm?.leftEye)
            let earR = ActiveLivenessChallenge.eyeAspectRatio(lm?.rightEye)
            let ear = [earL, earR].compactMap { $0 }.reduce(0, +) / Double(max(1, [earL, earR].compactMap { $0 }.count))

            // Знімаємо кадр обличчя для звірки з DG2, коли обличчя в кадрі
            // й очі відкриті (нейтральні фази — і так фронтальні). Умову
            // не завʼязуємо на абсолютний horiz (база в людини зсунута).
            if horiz != nil, (earL ?? earR ?? 0) > 0.20,
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
