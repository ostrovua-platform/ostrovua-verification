import Foundation
import SwiftUI
import AVFoundation
import Vision
import Combine
import ImageIO

// Работает на собственной очереди; публикации — вручную через main
final class FaceLivenessManager: NSObject, ObservableObject, @unchecked Sendable {
    @Published private(set) var result: FaceLivenessResult = .notStarted
    @Published private(set) var faceConfidence: Double = 0

    /// Кадр лица, снятый в момент подтверждения живости —
    /// используется для сверки с фото из DG2 чипа.
    @Published private(set) var capturedFace: UIImage?

    /// Живая подсказка как при регистрации Face ID:
    /// свет, позиция, дистанция. nil — всё хорошо, прогресс идёт.
    @Published private(set) var guidance: String?

    /// Публичный доступ для живого превью камеры на экране face check.
    let session = AVCaptureSession()
    private let videoOutput = AVCaptureVideoDataOutput()
    private let queue = DispatchQueue(label: "ostrovua.face.liveness.queue")

    private var completion: ((Bool) -> Void)?
    private var detectedFrameCount = 0
    private var startedAt: Date?

    func startCheck(completion: @escaping (Bool) -> Void) {
        self.completion = completion

        #if targetEnvironment(simulator)
        runSimulatorMock()
        #else
        requestCameraPermission()
        #endif
    }

    func stop() {
        if session.isRunning {
            session.stopRunning()
        }

        detectedFrameCount = 0
        startedAt = nil
        completion = nil
    }

    func reset() {
        stop()
        result = .notStarted
        faceConfidence = 0
        capturedFace = nil
        guidance = nil
    }

    private func complete(success: Bool) {
        DispatchQueue.main.async {
            self.completion?(success)
            self.completion = nil
        }
    }

    private func runSimulatorMock() {
        result = .searchingFace

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            self.faceConfidence = 1
            self.result = .livenessPassed("Demo-режим: обличчя та живість підтверджено.")
            self.complete(success: true)
        }
    }

    private func requestCameraPermission() {
        result = .requestingPermission

        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            configureCamera()

        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                DispatchQueue.main.async {
                    if granted {
                        self.configureCamera()
                    } else {
                        self.result = .failed("Доступ до камери відхилено.")
                        self.complete(success: false)
                    }
                }
            }

        case .denied, .restricted:
            result = .failed("Доступ до камери заборонено в налаштуваннях iOS.")
            complete(success: false)

        @unknown default:
            result = .failed("Невідомий статус доступу до камери.")
            complete(success: false)
        }
    }

    private func configureCamera() {
        result = .startingCamera

        queue.async {
            self.session.beginConfiguration()
            self.session.sessionPreset = .medium

            self.session.inputs.forEach { input in
                self.session.removeInput(input)
            }

            self.session.outputs.forEach { output in
                self.session.removeOutput(output)
            }

            guard let device = AVCaptureDevice.default(
                .builtInTrueDepthCamera,
                for: .video,
                position: .front
            ) ?? AVCaptureDevice.default(
                .builtInWideAngleCamera,
                for: .video,
                position: .front
            ) else {
                DispatchQueue.main.async {
                    self.result = .failed("Фронтальна камера недоступна.")
                    self.complete(success: false)
                }
                return
            }

            do {
                let input = try AVCaptureDeviceInput(device: device)

                guard self.session.canAddInput(input) else {
                    DispatchQueue.main.async {
                        self.result = .failed("Неможливо додати камеру до сесії.")
                        self.complete(success: false)
                    }
                    return
                }

                self.session.addInput(input)

                self.videoOutput.setSampleBufferDelegate(self, queue: self.queue)
                self.videoOutput.alwaysDiscardsLateVideoFrames = true

                guard self.session.canAddOutput(self.videoOutput) else {
                    DispatchQueue.main.async {
                        self.result = .failed("Неможливо додати відеовихід.")
                        self.complete(success: false)
                    }
                    return
                }

                self.session.addOutput(self.videoOutput)
                self.session.commitConfiguration()

                self.detectedFrameCount = 0
                self.startedAt = Date()

                DispatchQueue.main.async {
                    self.result = .searchingFace
                }

                self.session.startRunning()
            } catch {
                DispatchQueue.main.async {
                    self.result = .failed("Не вдалося увімкнути камеру. (E-403)")
                    self.complete(success: false)
                }
            }
        }
    }

    /// Скидання прогресу, коли обличчя загубилось / вийшло з умов.
    /// Гарантує ПОСЛІДОВНІСТЬ 12 кадрів, а не суму рваних.
    private func resetLivenessProgress() {
        guard detectedFrameCount > 0 else { return }
        detectedFrameCount = 0
        DispatchQueue.main.async { self.faceConfidence = 0 }
    }

    private func handleFaceDetected(pixelBuffer: CVPixelBuffer?) {
        detectedFrameCount += 1

        let confidence = min(Double(detectedFrameCount) / 12.0, 1)

        DispatchQueue.main.async {
            self.faceConfidence = confidence

            if confidence < 1 {
                self.result = .faceDetected
            }
        }

        if detectedFrameCount >= 12 {
            session.stopRunning()

            // Сохраняем кадр лица для сверки с фото из чипа (DG2)
            let faceImage = pixelBuffer.flatMap { Self.makeImage(from: $0) }

            DispatchQueue.main.async {
                self.capturedFace = faceImage
                self.result = .livenessPassed("Обличчя стабільно знайдено в кадрі. Перевірку живої присутності пройдено.")
                self.complete(success: true)
            }
        }
    }

    private static func makeImage(from pixelBuffer: CVPixelBuffer) -> UIImage? {
        let ciImage = CIImage(cvPixelBuffer: pixelBuffer).oriented(.leftMirrored)
        let context = CIContext()

        guard let cgImage = context.createCGImage(ciImage, from: ciImage.extent) else {
            return nil
        }

        return UIImage(cgImage: cgImage)
    }

    private func handleTimeoutIfNeeded() {
        guard let startedAt else {
            return
        }

        let elapsed = Date().timeIntervalSince(startedAt)

        if elapsed > 10 {
            session.stopRunning()

            DispatchQueue.main.async {
                self.result = .failed("Обличчя не знайдено. Спробуй ще раз при кращому освітленні.")
                self.complete(success: false)
            }
        }
    }
}

extension FaceLivenessManager: AVCaptureVideoDataOutputSampleBufferDelegate {
    func captureOutput(
        _ output: AVCaptureOutput,
        didOutput sampleBuffer: CMSampleBuffer,
        from connection: AVCaptureConnection
    ) {
        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else {
            return
        }

        let brightness = Self.brightness(of: sampleBuffer)

        let request = VNDetectFaceRectanglesRequest { [weak self] request, _ in
            guard let self else { return }

            let faces = request.results as? [VNFaceObservation] ?? []
            self.evaluate(face: faces.first, pixelBuffer: pixelBuffer, brightness: brightness)
        }

        let handler = VNImageRequestHandler(
            cvPixelBuffer: pixelBuffer,
            orientation: .leftMirrored,
            options: [:]
        )

        do {
            try handler.perform([request])
        } catch {
            handleTimeoutIfNeeded()
        }
    }

    /// Face ID-стиль: прогресс идёт только при хорошем свете,
    /// правильной дистанции и лице по центру кадра.
    private func evaluate(face: VNFaceObservation?, pixelBuffer: CVPixelBuffer, brightness: Double?) {
        guard let face else {
            // Обличчя зникло → прогрес liveness ОБНУЛЯЄТЬСЯ: кадри мають
            // бути ПОСЛІДОВНИМИ. Раніше лічильник не скидався — можна було
            // «набрати» 12 кадрів рваними шматками з різних облич/фото.
            resetLivenessProgress()
            setGuidance("Тримай обличчя в кадрі")
            handleTimeoutIfNeeded()
            return
        }

        // Мало света (EXIF BrightnessValue: < -1 — темно)
        if let brightness, brightness < -1 {
            resetLivenessProgress()
            setGuidance("Потрібно більше світла")
            return
        }

        let box = face.boundingBox

        // Слишком далеко / слишком близко
        if box.width < 0.22 {
            resetLivenessProgress()
            setGuidance("Наблизь обличчя до камери")
            return
        }
        if box.width > 0.75 {
            resetLivenessProgress()
            setGuidance("Трохи відсунься від камери")
            return
        }

        // Не по центру
        let dx = abs(box.midX - 0.5)
        let dy = abs(box.midY - 0.5)
        if dx > 0.2 || dy > 0.22 {
            resetLivenessProgress()
            setGuidance("Розташуй обличчя по центру кола")
            return
        }

        // Всё хорошо — прогресс идёт
        setGuidance(nil)
        handleFaceDetected(pixelBuffer: pixelBuffer)
    }

    private func setGuidance(_ text: String?) {
        DispatchQueue.main.async {
            if self.guidance != text {
                self.guidance = text
            }
        }
    }

    /// Яркость кадра из EXIF-метаданных сэмпла.
    private static func brightness(of sampleBuffer: CMSampleBuffer) -> Double? {
        guard
            let metadata = CMCopyDictionaryOfAttachments(
                allocator: nil,
                target: sampleBuffer,
                attachmentMode: kCMAttachmentMode_ShouldPropagate
            ) as? [String: Any],
            let exif = metadata[kCGImagePropertyExifDictionary as String] as? [String: Any],
            let value = exif[kCGImagePropertyExifBrightnessValue as String] as? Double
        else {
            return nil
        }

        return value
    }
}
