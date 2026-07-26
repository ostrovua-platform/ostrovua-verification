import Foundation
import ARKit
import Combine

/// ВИМІРЮВАЛЬНИЙ (не бойовий) зонд рельєфу глибини через TrueDepth/ARKit —
/// перший крок анти-реплею на Face ID (політика B). Ідея: живе обличчя
/// має РЕЛЬЄФ (нос ближче за щоки на 2–3 см), плоский екран/фото — ні.
/// Рахуємо СИРУ глибину (`ARFrame.capturedDepthData`) у центрі обличчя й
/// логуємо СТАНДАРТНЕ ВІДХИЛЕННЯ (метри) у колонку `depth`. Стенд збирає
/// bonafide vs photo/screen → `challenge_score.py` покаже, чи розділяються.
/// ⚠️ ПЕРША ВЕРСІЯ під ВИМІР. У бій — лише після того, як стенд доведе
/// розділення (той самий принцип, що врятував від depth-RMS). Face ID-only:
/// на пристроях без TrueDepth недоступно (SE 2/3 — гості).
final class DepthReliefManager: NSObject, ObservableObject {
    @Published private(set) var supported = ARFaceTrackingConfiguration.isSupported
    @Published private(set) var reliefText = "—"
    @Published private(set) var lastRelief: Double = 0

    let session = ARSession()

    func start() {
        guard ARFaceTrackingConfiguration.isSupported else {
            DispatchQueue.main.async {
                self.supported = false
                self.reliefText = "TrueDepth недоступний (потрібен Face ID)"
            }
            return
        }
        session.delegate = self
        let cfg = ARFaceTrackingConfiguration()
        cfg.isLightEstimationEnabled = false
        session.run(cfg, options: [.resetTracking, .removeExistingAnchors])
    }

    func stop() { session.pause() }

    /// Стандартне відхилення сирої глибини (метри) у ЦЕНТРАЛЬНОМУ вікні
    /// кадру — там ніс/щоки живого обличчя дають розкид, екран — майже 0.
    /// Центральне вікно замість мапінгу лендмарок: менше ризику помилки
    /// координат (саме він завалив ROI у depth-RMS). Груба, але чесна ознака.
    private func centralDepthStd(_ depthData: AVDepthData) -> Double? {
        let converted = depthData.converting(toDepthDataType: kCVPixelFormatType_DepthFloat32)
        let map = converted.depthDataMap
        CVPixelBufferLockBaseAddress(map, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(map, .readOnly) }

        guard let base = CVPixelBufferGetBaseAddress(map) else { return nil }
        let w = CVPixelBufferGetWidth(map)
        let h = CVPixelBufferGetHeight(map)
        let rowBytes = CVPixelBufferGetBytesPerRow(map)

        // Центральні 50% кадру (там обличчя, коли користувач у рамці).
        // v1 (перевірено виміром): сирий std у цьому вікні ЧИСТО ловить
        // екран (плоский → низький std). Полосу навколо медіани (v2)
        // ВІДКОЧЕНО — вона обрізала й рельєф живого обличчя, розділення
        // зникло. photo лікуємо інакше (обовʼязкове кліпання в челенджі
        // + семпл лише в межах обличчя — окремий крок).
        let x0 = w / 4, x1 = w * 3 / 4
        let y0 = h / 4, y1 = h * 3 / 4
        guard x1 > x0, y1 > y0 else { return nil }

        var sum = 0.0, sum2 = 0.0, n = 0
        var y = y0
        while y < y1 {
            let row = base.advanced(by: y * rowBytes).assumingMemoryBound(to: Float32.self)
            var x = x0
            while x < x1 {
                let d = Double(row[x])
                if d.isFinite, d > 0.05, d < 1.5 {      // 5 см…1.5 м — валідний діапазон обличчя
                    sum += d; sum2 += d * d; n += 1
                }
                x += 1
            }
            y += 1
        }
        guard n > 30 else { return nil }
        let mean = sum / Double(n)
        let variance = max(0, sum2 / Double(n) - mean * mean)
        return variance.squareRoot()
    }
}

extension DepthReliefManager: ARSessionDelegate {
    func session(_ session: ARSession, didUpdate frame: ARFrame) {
        // Рахуємо лише коли ARKit БАЧИТЬ обличчя (є face anchor).
        guard frame.anchors.contains(where: { $0 is ARFaceAnchor }),
              let depth = frame.capturedDepthData,
              let std = centralDepthStd(depth) else { return }

        DispatchQueue.main.async {
            self.lastRelief = std
            self.reliefText = String(format: "рельєф глибини: %.4f м (std)", std)
        }
        // Пишемо у колонку depth стенда з поточною міткою.
        ChallengeLogger.shared.frame(state: "depth", yaw: nil, pitch: nil, ear: nil,
                                     depth: std)
    }
}
