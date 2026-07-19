import Foundation
import CoreML
import CoreImage
import UIKit

/// Специализированная face-recognition модель (FaceNet / ArcFace) через CoreML.
///
/// Ищет в бандле модель «FaceEmbedding» (.mlmodelc — Xcode компилирует
/// .mlpackage/.mlmodel автоматически). Если модель добавлена в проект,
/// FaceMatcher использует её вместо VNFeaturePrint — точность распознавания
/// личности вырастает кратно. Конвертация модели: Tools/convert_face_model.py.
final class FaceEmbedder {
    static let shared = FaceEmbedder()

    private let model: MLModel?
    private let inputName: String
    private let inputSize: CGSize
    private let ciContext = CIContext()

    private init() {
        guard let url = Bundle.main.url(forResource: "FaceEmbedding", withExtension: "mlmodelc"),
              let loaded = try? MLModel(contentsOf: url) else {
            model = nil
            inputName = ""
            inputSize = .zero
            return
        }

        model = loaded

        // Имя и размер входа читаем из описания модели — подходит и FaceNet (160×160), и MobileFaceNet (112×112)
        if let (name, constraint) = loaded.modelDescription.inputDescriptionsByName.first(where: { $0.value.imageConstraint != nil }),
           let image = constraint.imageConstraint {
            inputName = name
            inputSize = CGSize(width: image.pixelsWide, height: image.pixelsHigh)
        } else {
            inputName = ""
            inputSize = .zero
        }
    }

    var isAvailable: Bool {
        model != nil && inputName.isEmpty == false
    }

    /// 512-мерный (или иной) вектор лица. Вход — выровненное и кадрированное лицо.
    func embedding(for face: CGImage) throws -> [Float] {
        guard let model, inputName.isEmpty == false else {
            throw FaceMatchError.featurePrintFailed
        }

        guard let pixelBuffer = makePixelBuffer(from: face, size: inputSize) else {
            throw FaceMatchError.invalidImage
        }

        let input = try MLDictionaryFeatureProvider(
            dictionary: [inputName: MLFeatureValue(pixelBuffer: pixelBuffer)]
        )

        let output = try model.prediction(from: input)

        guard
            let featureName = output.featureNames.first,
            let array = output.featureValue(for: featureName)?.multiArrayValue
        else {
            throw FaceMatchError.featurePrintFailed
        }

        var vector = [Float](repeating: 0, count: array.count)
        for i in 0..<array.count {
            vector[i] = array[i].floatValue
        }

        // L2-нормализация — косинус потом считается простым скалярным произведением
        let norm = sqrt(vector.reduce(0) { $0 + $1 * $1 })
        guard norm > 0 else {
            throw FaceMatchError.featurePrintFailed
        }

        return vector.map { $0 / norm }
    }

    static func cosineSimilarity(_ a: [Float], _ b: [Float]) -> Float {
        guard a.count == b.count, a.isEmpty == false else {
            return 0
        }
        return zip(a, b).reduce(0) { $0 + $1.0 * $1.1 }
    }

    // MARK: - CGImage → CVPixelBuffer нужного размера

    private func makePixelBuffer(from cgImage: CGImage, size: CGSize) -> CVPixelBuffer? {
        var buffer: CVPixelBuffer?
        let attributes: [CFString: Any] = [
            kCVPixelBufferCGImageCompatibilityKey: true,
            kCVPixelBufferCGBitmapContextCompatibilityKey: true
        ]

        CVPixelBufferCreate(
            kCFAllocatorDefault,
            Int(size.width),
            Int(size.height),
            kCVPixelFormatType_32BGRA,
            attributes as CFDictionary,
            &buffer
        )

        guard let buffer else {
            return nil
        }

        let ciImage = CIImage(cgImage: cgImage)
        let scaleX = size.width / CGFloat(cgImage.width)
        let scaleY = size.height / CGFloat(cgImage.height)
        let scaled = ciImage.transformed(by: CGAffineTransform(scaleX: scaleX, y: scaleY))

        ciContext.render(scaled, to: buffer)
        return buffer
    }
}
