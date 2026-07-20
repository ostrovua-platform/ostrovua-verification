import UIKit
import Vision
import CoreImage

/// Результат сверки живого лица с фото из DG2 чипа.
enum FaceMatchVerdict {
    case match(similarity: Double)       // уверенное совпадение
    case uncertain(similarity: Double)   // пограничный случай — повторить
    case noMatch(similarity: Double)     // другое лицо
}

/// Вердикт + яка модель фактично рахувала — щоб чесно повідомити
/// серверу (evidence.faceModel) і не приховувати зниження гарантій.
struct FaceMatchResultDetail {
    let verdict: FaceMatchVerdict
    let model: String   // "coreml" | "vision_fallback"
}

/// Сверка лица с камеры с фото владельца из чипа документа (DG2).
///
/// Пайплайн: детекция лица → выравнивание по линии глаз → кадрирование →
/// сравнение по косинусу face-эмбеддингов CoreML-модели «FaceEmbedding»
/// (FaceNet, см. Tools/convert_face_model.py; hash — Provenance/MODEL.md).
/// В RELEASE модель ОБЯЗАТЕЛЬНА: без неё верификация падает с
/// modelUnavailable. Fallback на VNFeaturePrint существует только
/// в DEBUG-сборках для разработки без модели.
enum FaceMatcher {

    // Пороги косинусной близости для FaceNet-эмбеддингов
    private static let embeddingMatch: Float = 0.60
    private static let embeddingUncertain: Float = 0.45

    // Пороги дистанции VNFeaturePrint (fallback)
    private static let printMatch: Float = 0.85
    private static let printUncertain: Float = 1.05

    static func match(chipPhoto: UIImage, liveFace: UIImage) async throws -> FaceMatchResultDetail {
        try await Task.detached(priority: .userInitiated) {
            let chipCrop = try alignedFace(from: chipPhoto)
            let liveCrop = try alignedFace(from: liveFace)

            if FaceEmbedder.shared.isAvailable {
                let verdict = try matchWithEmbeddings(chipCrop, liveCrop)
                return FaceMatchResultDetail(verdict: verdict, model: "coreml")
            }

            // РЕЛІЗ: тихий fallback на VNFeaturePrint заборонено — це
            // знизило б гарантії без відома сервера й користувача.
            // Vision FeaturePrint — інструмент подібності зображень,
            // а не біометричне підтвердження особи.
            #if DEBUG
            let verdict = try matchWithFeaturePrints(chipCrop, liveCrop)
            return FaceMatchResultDetail(verdict: verdict, model: "vision_fallback")
            #else
            throw FaceMatchError.modelUnavailable
            #endif
        }.value
    }

    // MARK: - Сравнение face-эмбеддингами (CoreML-модель)

    private static func matchWithEmbeddings(_ a: CGImage, _ b: CGImage) throws -> FaceMatchVerdict {
        let ea = try FaceEmbedder.shared.embedding(for: a)
        let eb = try FaceEmbedder.shared.embedding(for: b)

        let cosine = FaceEmbedder.cosineSimilarity(ea, eb)
        let similarity = Double(max(0, min(1, (cosine + 1) / 2)))

        if cosine >= embeddingMatch {
            return .match(similarity: similarity)
        } else if cosine >= embeddingUncertain {
            return .uncertain(similarity: similarity)
        } else {
            return .noMatch(similarity: similarity)
        }
    }

    // MARK: - Fallback: VNFeaturePrint

    private static func matchWithFeaturePrints(_ a: CGImage, _ b: CGImage) throws -> FaceMatchVerdict {
        let pa = try featurePrint(for: a)
        let pb = try featurePrint(for: b)

        var distance: Float = 0
        try pa.computeDistance(&distance, to: pb)

        let similarity = Double(max(0, min(1, 1 - distance / 1.4)))

        if distance < printMatch {
            return .match(similarity: similarity)
        } else if distance < printUncertain {
            return .uncertain(similarity: similarity)
        } else {
            return .noMatch(similarity: similarity)
        }
    }

    private static func featurePrint(for cgImage: CGImage) throws -> VNFeaturePrintObservation {
        let request = VNGenerateImageFeaturePrintRequest()
        let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
        try handler.perform([request])

        guard let observation = request.results?.first as? VNFeaturePrintObservation else {
            throw FaceMatchError.featurePrintFailed
        }

        return observation
    }

    // MARK: - Детекция, выравнивание и кадрирование лица

    /// Находит лицо, поворачивает изображение так, чтобы линия глаз была
    /// горизонтальной (важно для точности эмбеддингов), кадрирует с запасом.
    private static func alignedFace(from image: UIImage) throws -> CGImage {
        guard let cgImage = normalizedCGImage(from: image) else {
            throw FaceMatchError.invalidImage
        }

        let request = VNDetectFaceLandmarksRequest()
        let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
        try handler.perform([request])

        guard let face = (request.results ?? []).first else {
            throw FaceMatchError.faceNotFound
        }

        // Угол наклона по центрам глаз
        var rotated = cgImage
        var faceBox = face.boundingBox

        if let landmarks = face.landmarks,
           let left = landmarks.leftEye,
           let right = landmarks.rightEye {

            let leftCenter = averagePoint(left.normalizedPoints)
            let rightCenter = averagePoint(right.normalizedPoints)

            // Точки нормализованы внутри boundingBox лица → в координаты изображения
            let lx = (faceBox.minX + leftCenter.x * faceBox.width)
            let ly = (faceBox.minY + leftCenter.y * faceBox.height)
            let rx = (faceBox.minX + rightCenter.x * faceBox.width)
            let ry = (faceBox.minY + rightCenter.y * faceBox.height)

            let angle = atan2(ry - ly, rx - lx)

            // Поворачиваем только при заметном наклоне (> 3°)
            if abs(angle) > .pi / 60, let result = rotate(cgImage, by: -angle) {
                rotated = result

                // Переопределяем лицо на повёрнутом изображении
                let redetect = VNDetectFaceRectanglesRequest()
                let rehandler = VNImageRequestHandler(cgImage: rotated, options: [:])
                try? rehandler.perform([redetect])

                if let newFace = (redetect.results ?? []).first {
                    faceBox = newFace.boundingBox
                }
            }
        }

        return try crop(rotated, normalizedBox: faceBox)
    }

    private static func crop(_ cgImage: CGImage, normalizedBox box: CGRect) throws -> CGImage {
        let width = CGFloat(cgImage.width)
        let height = CGFloat(cgImage.height)

        let padX = box.width * 0.3
        let padY = box.height * 0.3

        let rect = CGRect(
            x: max(0, (box.minX - padX) * width),
            y: max(0, (1 - box.maxY - padY) * height),
            width: min(width, (box.width + padX * 2) * width),
            height: min(height, (box.height + padY * 2) * height)
        ).integral

        guard let crop = cgImage.cropping(to: rect) else {
            throw FaceMatchError.invalidImage
        }

        return crop
    }

    private static func rotate(_ cgImage: CGImage, by angle: CGFloat) -> CGImage? {
        let ciImage = CIImage(cgImage: cgImage)
        let rotated = ciImage.transformed(by: CGAffineTransform(rotationAngle: angle))
        let context = CIContext()
        return context.createCGImage(rotated, from: rotated.extent)
    }

    /// UIImage может иметь EXIF-ориентацию — приводим к «сырому» CGImage без поворотов.
    private static func normalizedCGImage(from image: UIImage) -> CGImage? {
        if image.imageOrientation == .up {
            return image.cgImage
        }

        UIGraphicsBeginImageContextWithOptions(image.size, false, 1)
        defer { UIGraphicsEndImageContext() }
        image.draw(in: CGRect(origin: .zero, size: image.size))
        return UIGraphicsGetImageFromCurrentImageContext()?.cgImage
    }

    private static func averagePoint(_ points: [CGPoint]) -> CGPoint {
        guard points.isEmpty == false else {
            return .zero
        }
        let sum = points.reduce(CGPoint.zero) { CGPoint(x: $0.x + $1.x, y: $0.y + $1.y) }
        return CGPoint(x: sum.x / CGFloat(points.count), y: sum.y / CGFloat(points.count))
    }
}

enum FaceMatchError: LocalizedError {
    case invalidImage
    case faceNotFound
    case featurePrintFailed
    case modelUnavailable

    var errorDescription: String? {
        switch self {
        case .invalidImage:
            return trs("Не вдалося обробити зображення.")
        case .faceNotFound:
            return trs("Обличчя не знайдено на зображенні.")
        case .featurePrintFailed:
            return trs("Не вдалося побудувати відбиток обличчя.")
        case .modelUnavailable:
            return trs("Модель звірки обличчя недоступна. Верифікацію не можна пройти на цьому пристрої.")
        }
    }
}
