import Foundation
import SwiftUI
import AVFoundation
import Combine

#if canImport(ARKit)
import ARKit
#endif

final class CameraDepthVerificationManager: NSObject, ObservableObject {
    @Published private(set) var result: CameraVerificationResult = .notStarted

    private var completion: ((Bool) -> Void)?

    #if canImport(ARKit)
    private let arSession = ARSession()
    private var didComplete = false
    #endif

    func startCheck(completion: @escaping (Bool) -> Void) {
        self.completion = completion

        #if targetEnvironment(simulator)
        runSimulatorMock()
        #else
        requestCameraPermission()
        #endif
    }

    func reset() {
        result = .notStarted
        completion = nil

        #if canImport(ARKit)
        didComplete = false
        arSession.pause()
        #endif
    }

    private func complete(success: Bool) {
        completion?(success)
        completion = nil
    }

    private func runSimulatorMock() {
        result = .scanning

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            self.result = .success("Demo-режим: перевірку камери успішно пройдено.")
            self.complete(success: true)
        }
    }

    private func requestCameraPermission() {
        result = .requestingPermission

        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            startDepthSession()

        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                DispatchQueue.main.async {
                    if granted {
                        self.startDepthSession()
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

    private func startDepthSession() {
        #if canImport(ARKit)
        guard ARWorldTrackingConfiguration.isSupported else {
            result = .failed("ARKit недоступний на цьому пристрої.")
            complete(success: false)
            return
        }

        let configuration = ARWorldTrackingConfiguration()

        if ARWorldTrackingConfiguration.supportsFrameSemantics(.sceneDepth) {
            configuration.frameSemantics.insert(.sceneDepth)
        } else if ARWorldTrackingConfiguration.supportsFrameSemantics(.smoothedSceneDepth) {
            configuration.frameSemantics.insert(.smoothedSceneDepth)
        } else {
            result = .failed("LiDAR / depth недоступний на цьому пристрої. Можна перейти на fallback-перевірку камерою.")
            complete(success: false)
            return
        }

        result = .scanning
        didComplete = false

        arSession.delegate = self
        arSession.run(
            configuration,
            options: [
                .resetTracking,
                .removeExistingAnchors
            ]
        )
        #else
        result = .failed("ARKit недоступний у цьому середовищі.")
        complete(success: false)
        #endif
    }
}

#if canImport(ARKit)

extension CameraDepthVerificationManager: ARSessionDelegate {
    func session(_ session: ARSession, didUpdate frame: ARFrame) {
        guard didComplete == false else {
            return
        }

        let hasSceneDepth = frame.sceneDepth != nil
        let hasSmoothedDepth = frame.smoothedSceneDepth != nil

        if hasSceneDepth || hasSmoothedDepth {
            didComplete = true
            session.pause()

            DispatchQueue.main.async {
                self.result = .success("LiDAR / depth-кадр отримано. Камерну перевірку пройдено.")
                self.complete(success: true)
            }
        }
    }

    func session(_ session: ARSession, didFailWithError error: Error) {
        DispatchQueue.main.async {
            self.result = .failed("Камера глибини недоступна. (E-404)")
            self.complete(success: false)
        }
    }

    func sessionWasInterrupted(_ session: ARSession) {
        DispatchQueue.main.async {
            self.result = .failed("AR-сесію перервано.")
            self.complete(success: false)
        }
    }
}

#endif
