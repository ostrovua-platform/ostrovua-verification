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
    private let depthOutput = AVCaptureDepthDataOutput()
    private let queue = DispatchQueue(label: "ostrovua.face.liveness.queue")

    private var completion: ((Bool) -> Void)?
    private var detectedFrameCount = 0
    private var startedAt: Date?

    /// TrueDepth доступний і налаштований → кожен зарахований кадр
    /// зобовʼязаний пройти перевірку ОБʼЄМНОСТІ обличчя (анти-фото).
    private var depthSupported = false
    /// Остання мапа глибини (пишеться і читається на self.queue).
    private var latestDepth: AVDepthData?

    /// Який режим liveness РЕАЛЬНО відпрацював — чесно йде на сервер:
    /// "depth" (TrueDepth: площина = відмова) або "heuristic" (без депту).
    private(set) var livenessMode: String = "heuristic"

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
        queue.async { self.latestDepth = nil }
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

                // ── TrueDepth: реальна перевірка обʼємності (анти-фото) ──
                // Мапа глибини з того ж сенсора, що й Face ID. ВАЖЛИВО:
                // пресети (.medium тощо) часто обирають відеоформат БЕЗ
                // підтримки глибини — тому явно шукаємо формат з depth
                // (класика TrueDepth — 640×480) і вмикаємо .inputPriority.
                // На пристроях без TrueDepth (SE) — чесний "heuristic".
                var depthReady = false
                if device.deviceType == .builtInTrueDepthCamera,
                   self.session.canAddOutput(self.depthOutput) {

                    func depthFormats(of format: AVCaptureDevice.Format) -> [AVCaptureDevice.Format] {
                        format.supportedDepthDataFormats.filter {
                            let subtype = CMFormatDescriptionGetMediaSubType($0.formatDescription)
                            return subtype == kCVPixelFormatType_DepthFloat16
                                || subtype == kCVPixelFormatType_DepthFloat32
                        }
                    }

                    // Відеоформат з глибиною, ближчий до 640 px по ширині
                    let candidates = device.formats.filter { depthFormats(of: $0).isEmpty == false }
                    let videoFormat = candidates.min { a, b in
                        let wa = CMVideoFormatDescriptionGetDimensions(a.formatDescription).width
                        let wb = CMVideoFormatDescriptionGetDimensions(b.formatDescription).width
                        return abs(wa - 640) < abs(wb - 640)
                    }

                    if let videoFormat,
                       let depthFormat = depthFormats(of: videoFormat).max(by: {
                           CMVideoFormatDescriptionGetDimensions($0.formatDescription).width
                               < CMVideoFormatDescriptionGetDimensions($1.formatDescription).width
                       }) {
                        do {
                            self.session.sessionPreset = .inputPriority
                            try device.lockForConfiguration()
                            device.activeFormat = videoFormat
                            device.activeDepthDataFormat = depthFormat
                            device.unlockForConfiguration()

                            self.session.addOutput(self.depthOutput)
                            self.depthOutput.isFilteringEnabled = true
                            self.depthOutput.setDelegate(self, callbackQueue: self.queue)
                            depthReady = true
                        } catch {
                            self.session.sessionPreset = .medium
                            depthReady = false
                        }
                    }
                }
                self.depthSupported = depthReady
                self.latestDepth = nil

                self.session.commitConfiguration()

                // ПОЛІТИКА (рішення після аудитів): Verified ID видається
                // ЛИШЕ з перевіркою обʼємності. Без TrueDepth (SE, до
                // iPhone X) верифікація чесно недоступна — ніякого
                // «тихого» зниження рівня до евристики.
                guard depthReady else {
                    DispatchQueue.main.async {
                        self.result = .failed(
                            "Для верифікації потрібен iPhone з Face ID (TrueDepth). Пристрої без нього наразі не підтримуються. (E-406)"
                        )
                        self.complete(success: false)
                    }
                    return
                }

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

    private func handleFaceDetected(pixelBuffer: CVPixelBuffer?, faceBox: CGRect) {
        // ── Ворота глибини (TrueDepth) ────────────────────────────────
        // Кадр зараховується ЛИШЕ якщо мапа глибини показує рельєф
        // обличчя. Плоске фото/екран (навіть нахилене — площину-фіт
        // нахил не обманює) кадрів не набере → таймаут. Кадр без
        // свіжої глибини просто не зараховується (без скидання).
        if depthSupported {
            guard let depth = latestDepth,
                  Self.isVolumetricFace(depth, faceBox: faceBox) else {
                return
            }
        }

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

            // Чесний режим для сервера: що РЕАЛЬНО перевірено
            livenessMode = depthSupported ? "depth" : "heuristic"

            // Сохраняем кадр лица для сверки с фото из чипа (DG2)
            let faceImage = pixelBuffer.flatMap { Self.makeImage(from: $0) }

            DispatchQueue.main.async {
                self.capturedFace = faceImage
                self.result = .livenessPassed("Обличчя стабільно знайдено в кадрі. Перевірку живої присутності пройдено.")
                self.complete(success: true)
            }
        }
    }

    // MARK: - Обʼємність обличчя за мапою глибини (анти-фото/екран)

    /// Least-squares площина по центральному вікну кадру глибини +
    /// RMS-залишок. Фото/екран — площина (залишок ~шум сенсора, <2–3 мм)
    /// незалежно від нахилу. Живе обличчя — ніс/щоки дають кривизну,
    /// залишок ≥ ~5 мм. Це НЕ сертифікований PAD (маска обманить),
    /// але клас атак «фото та відео з екрана» закриває по-справжньому.
    private static func isVolumetricFace(_ depthData: AVDepthData, faceBox: CGRect) -> Bool {
        let depth32: AVDepthData
        if depthData.depthDataType == kCVPixelFormatType_DepthFloat32 {
            depth32 = depthData
        } else {
            depth32 = depthData.converting(toDepthDataType: kCVPixelFormatType_DepthFloat32)
        }

        let map = depth32.depthDataMap
        CVPixelBufferLockBaseAddress(map, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(map, .readOnly) }

        guard let base = CVPixelBufferGetBaseAddress(map) else { return false }
        let width = CVPixelBufferGetWidth(map)
        let height = CVPixelBufferGetHeight(map)
        let rowBytes = CVPixelBufferGetBytesPerRow(map)

        // Вікно: центр кадру, сторона ~ розміру обличчя (обличчя і так
        // з-gate-но по центру й розміру перед цим викликом).
        let minDim = CGFloat(min(width, height))
        let side = Int(max(0.18, min(0.5, min(faceBox.width, faceBox.height) * 0.7)) * minDim)
        let x0 = (width - side) / 2
        let y0 = (height - side) / 2

        // Сітка 20×20: точки (x, y, z)
        var xs: [Double] = [], ys: [Double] = [], zs: [Double] = []
        let grid = 20
        let step = max(1, side / grid)

        for gy in stride(from: y0, to: y0 + side, by: step) {
            let row = base.advanced(by: gy * rowBytes).assumingMemoryBound(to: Float32.self)
            for gx in stride(from: x0, to: x0 + side, by: step) {
                let z = Double(row[gx])
                // Валідна дистанція обличчя: 15 см — 1 м
                if z.isFinite, z > 0.15, z < 1.0 {
                    xs.append(Double(gx)); ys.append(Double(gy)); zs.append(z)
                }
            }
        }

        // Мало валідних точок → сенсор не бачить рельєфу (не зараховуємо)
        let expected = (side / step) * (side / step)
        guard zs.count >= max(30, expected * 55 / 100) else { return false }

        // Площина z = ax + by + c: нормальні рівняння 3×3 (Крамер)
        let n = Double(zs.count)
        var sx = 0.0, sy = 0.0, sz = 0.0, sxx = 0.0, syy = 0.0, sxy = 0.0, sxz = 0.0, syz = 0.0
        for i in 0..<zs.count {
            let x = xs[i], y = ys[i], z = zs[i]
            sx += x; sy += y; sz += z
            sxx += x * x; syy += y * y; sxy += x * y
            sxz += x * z; syz += y * z
        }
        let det = sxx * (syy * n - sy * sy) - sxy * (sxy * n - sy * sx) + sx * (sxy * sy - syy * sx)
        guard abs(det) > 1e-9 else { return false }

        let a = (sxz * (syy * n - sy * sy) - sxy * (syz * n - sy * sz) + sx * (syz * sy - syy * sz)) / det
        let b = (sxx * (syz * n - sz * sy) - sxz * (sxy * n - sx * sy) + sx * (sxy * sz - sx * syz)) / det
        let c = (sxx * (syy * sz - sy * syz) - sxy * (sxy * sz - sx * syz) + sxz * (sxy * sy - sx * syy)) / det

        var ss = 0.0
        for i in 0..<zs.count {
            let r = zs[i] - (a * xs[i] + b * ys[i] + c)
            ss += r * r
        }
        let rms = (ss / n).squareRoot()

        // Рельєф живого обличчя: RMS-залишок від площини ≥ 5 мм
        return rms >= 0.005
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

extension FaceLivenessManager: AVCaptureDepthDataOutputDelegate {
    func depthDataOutput(
        _ output: AVCaptureDepthDataOutput,
        didOutput depthData: AVDepthData,
        timestamp: CMTime,
        connection: AVCaptureConnection
    ) {
        // Той самий queue, що й відео — гонок немає
        latestDepth = depthData
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
        handleFaceDetected(pixelBuffer: pixelBuffer, faceBox: box)
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
