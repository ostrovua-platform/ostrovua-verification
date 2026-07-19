import Foundation
import SwiftUI
import AVFoundation
import Vision
import Combine

/// Сканер MRZ через камеру: Vision распознаёт текст в кадре,
/// строки-кандидаты проверяются чек-цифрами ICAO 9303 (PassportMRZ.parse).
// Работает на собственной очереди; публикации — вручную через main
final class MRZScannerManager: NSObject, ObservableObject, @unchecked Sendable {
    @Published private(set) var scannedMRZ: PassportMRZ?
    @Published private(set) var isRunning = false
    @Published private(set) var permissionDenied = false

    let session = AVCaptureSession()

    private let videoOutput = AVCaptureVideoDataOutput()
    private let queue = DispatchQueue(label: "ostrovua.mrz.scanner.queue")
    private var lastProcessedAt = Date.distantPast
    private var isConfigured = false

    func start() {
        scannedMRZ = nil

        #if targetEnvironment(simulator)
        // В симуляторе камеры нет — оставляем экран в режиме ожидания.
        isRunning = true
        return
        #else
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            configureAndRun()

        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    if granted {
                        self?.configureAndRun()
                    } else {
                        self?.permissionDenied = true
                    }
                }
            }

        default:
            permissionDenied = true
        }
        #endif
    }

    func stop() {
        guard session.isRunning else {
            isRunning = false
            return
        }

        queue.async { [weak self] in
            self?.session.stopRunning()
            DispatchQueue.main.async {
                self?.isRunning = false
            }
        }
    }

    private func configureAndRun() {
        queue.async { [weak self] in
            guard let self else { return }

            if self.isConfigured == false {
                self.session.beginConfiguration()
                self.session.sessionPreset = .high

                guard
                    let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back),
                    let input = try? AVCaptureDeviceInput(device: device),
                    self.session.canAddInput(input)
                else {
                    self.session.commitConfiguration()
                    return
                }

                self.session.addInput(input)

                self.videoOutput.setSampleBufferDelegate(self, queue: self.queue)
                if self.session.canAddOutput(self.videoOutput) {
                    self.session.addOutput(self.videoOutput)
                }

                self.session.commitConfiguration()
                self.isConfigured = true
            }

            self.session.startRunning()

            DispatchQueue.main.async {
                self.isRunning = true
            }
        }
    }

    private func handleRecognizedLines(_ lines: [String]) {
        for raw in lines {
            let candidate = raw
                .replacingOccurrences(of: " ", with: "")
                .uppercased()

            // Вторая строка MRZ TD3: 40–44 символа из A–Z, 0–9, '<'
            guard
                candidate.count >= 40,
                candidate.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "<" })
            else {
                continue
            }

            if let mrz = PassportMRZ.parse(mrzLine: candidate) {
                DispatchQueue.main.async {
                    guard self.scannedMRZ == nil else { return }
                    self.scannedMRZ = mrz
                    self.stop()
                }
                return
            }
        }
    }
}

extension MRZScannerManager: AVCaptureVideoDataOutputSampleBufferDelegate {
    func captureOutput(
        _ output: AVCaptureOutput,
        didOutput sampleBuffer: CMSampleBuffer,
        from connection: AVCaptureConnection
    ) {
        // Не чаще ~3 кадров в секунду
        guard Date().timeIntervalSince(lastProcessedAt) > 0.35 else {
            return
        }
        lastProcessedAt = Date()

        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else {
            return
        }

        let request = VNRecognizeTextRequest { [weak self] request, _ in
            let lines = (request.results as? [VNRecognizedTextObservation])?
                .compactMap { $0.topCandidates(1).first?.string } ?? []
            self?.handleRecognizedLines(lines)
        }
        request.recognitionLevel = .fast
        request.usesLanguageCorrection = false

        let handler = VNImageRequestHandler(cvPixelBuffer: pixelBuffer, orientation: .right)
        try? handler.perform([request])
    }
}

// MARK: - Превью камеры для SwiftUI

struct MRZCameraPreview: UIViewRepresentable {
    let session: AVCaptureSession

    func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView()
        view.videoPreviewLayer.session = session
        view.videoPreviewLayer.videoGravity = .resizeAspectFill
        return view
    }

    func updateUIView(_ uiView: PreviewView, context: Context) {}

    final class PreviewView: UIView {
        override class var layerClass: AnyClass {
            AVCaptureVideoPreviewLayer.self
        }

        var videoPreviewLayer: AVCaptureVideoPreviewLayer {
            layer as! AVCaptureVideoPreviewLayer
        }
    }
}
