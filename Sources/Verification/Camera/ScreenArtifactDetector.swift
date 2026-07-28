import CoreVideo
import CoreGraphics

/// ВИМІРЮВАНИЙ (ще НЕ бойовий) детектор артефактів екрана для стенда —
/// перший крок анти-реплею (Update 9 F). Екран/друге відео дає:
///   • МУАР / високу частоту — піксельна сітка екрана піднімає градієнт;
///   • ВІДБЛИСК (глар) — дзеркальні пересвіти скла екрана.
/// Рахуємо СИРІ ознаки по Y-площині (яскравість) у межах обличчя. Стенд
/// їх логує → `challenge_score.py` міряє розділення bonafide vs screen.
/// ⚠️ НЕ гейт: інтегруємо в бойовий флоу ЛИШЕ після виміру на пристрої
/// (той самий принцип «виміряй → потім довіряй», що врятував нас від
/// depth-RMS). Раніше нічого не блокує.
struct ScreenArtifacts {
    let glareFraction: Double   // частка майже-білих пікселів (0…1)
    let hfEnergy: Double        // середній градієнт (|dx|+|dy|)/255 — висока частота
    let sampled: Int            // розмір вибірки (0 = не рахували)

    static let empty = ScreenArtifacts(glareFraction: 0, hfEnergy: 0, sampled: 0)
}

enum ScreenArtifactDetector {

    /// pixelBuffer — 420 bi-planar (Y у площині 0); faceBox — нормалізований
    /// bbox Vision (origin низ-ліво). Повертає сирі ознаки для логування.
    static func analyze(_ pixelBuffer: CVPixelBuffer, faceBox: CGRect) -> ScreenArtifacts {
        guard CVPixelBufferGetPlaneCount(pixelBuffer) >= 1 else { return .empty }

        CVPixelBufferLockBaseAddress(pixelBuffer, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, .readOnly) }

        guard let base = CVPixelBufferGetBaseAddressOfPlane(pixelBuffer, 0) else { return .empty }
        let w        = CVPixelBufferGetWidthOfPlane(pixelBuffer, 0)
        let h        = CVPixelBufferGetHeightOfPlane(pixelBuffer, 0)
        let rowBytes = CVPixelBufferGetBytesPerRowOfPlane(pixelBuffer, 0)
        let ptr      = base.assumingMemoryBound(to: UInt8.self)

        // Vision bbox: y вгору; Y-площина: рядок 0 — верх → перевертаємо y.
        // Трохи стискаємо до центру обличчя (менше фону/волосся/країв).
        let roi = faceBox.insetBy(dx: faceBox.width * 0.15, dy: faceBox.height * 0.15)
        let x0 = max(1,     Int(roi.minX * CGFloat(w)))
        let x1 = min(w - 2, Int(roi.maxX * CGFloat(w)))
        let y0 = max(1,     Int((1 - roi.maxY) * CGFloat(h)))
        let y1 = min(h - 2, Int((1 - roi.minY) * CGFloat(h)))
        guard x1 - x0 > 4, y1 - y0 > 4 else { return .empty }

        var glare = 0
        var grad  = 0.0
        var n     = 0

        var y = y0
        while y <= y1 {
            let row   = ptr + y * rowBytes
            let rowUp = ptr + (y - 1) * rowBytes
            var x = x0
            while x <= x1 {
                let v = Int(row[x])
                if v >= 235 { glare += 1 }                    // майже-білий → глар
                let dx = abs(v - Int(row[x + 1]))             // горизонтальний градієнт
                let dy = abs(v - Int(rowUp[x]))               // вертикальний градієнт
                grad += Double(dx + dy)
                n += 1
                x += 1
            }
            y += 1
        }
        guard n > 0 else { return .empty }
        return ScreenArtifacts(
            glareFraction: Double(glare) / Double(n),
            hfEnergy: (grad / Double(n)) / 255.0,
            sampled: n
        )
    }
}
