// ═══════════════════════════════════════════════════════════════════
//  FaceEval — вимірювання FAR/FRR моделі FaceEmbedding на датасеті пар.
//
//  Препроцесинг ДОСЛІВНО повторює застосунок:
//   • вирівнювання обличчя — як FaceMatcher.alignedFace (Vision-лендмарки,
//     поворот по лінії очей, кадрування з полем 0.3);
//   • ембеддинг — як FaceEmbedder (вхід/розмір/вихід читаються з моделі,
//     L2-нормалізація, косинус скалярним добутком);
//   • поріг збігу — той самий embeddingMatch = 0.60 (raw cosine).
//
//  Запуск (macOS):
//    swift run -c release FaceEval \
//      --model /шлях/FaceEmbedding.mlpackage \
//      --lfw   /шлях/lfw \
//      --pairs /шлях/pairs.txt \
//      [--threshold 0.60] [--roc roc.csv]
//
//  Вихід: FAR/FRR при порозі, EER, AUC, повний ROC у CSV.
// ═══════════════════════════════════════════════════════════════════
import Foundation
import CoreML
import Vision
import CoreImage
import ImageIO

// MARK: - Аргументи

func arg(_ name: String) -> String? {
    guard let i = CommandLine.arguments.firstIndex(of: name),
          i + 1 < CommandLine.arguments.count else { return nil }
    return CommandLine.arguments[i + 1]
}
if CommandLine.arguments.contains("--help") || arg("--model") == nil {
    print("""
    FaceEval --model <FaceEmbedding.mlpackage|.mlmodelc> --lfw <dir> --pairs <pairs.txt>
             [--threshold 0.60] [--roc roc.csv]
    Датасет: Labeled Faces in the Wild (funneled/deepfunneled), файл pairs.txt.
    """)
    exit(arg("--model") == nil ? 1 : 0)
}
let modelPath = arg("--model")!
let lfwDir = arg("--lfw") ?? "lfw"
let pairsPath = arg("--pairs") ?? "pairs.txt"
let matchThreshold = Float(arg("--threshold") ?? "0.60") ?? 0.60
let rocPath = arg("--roc")

// MARK: - Завантаження моделі (як FaceEmbedder)

func loadModel(_ path: String) throws -> (MLModel, String, CGSize) {
    let url = URL(fileURLWithPath: path)
    let compiled: URL
    if path.hasSuffix(".mlmodelc") {
        compiled = url
    } else {
        compiled = try MLModel.compileModel(at: url)   // .mlpackage/.mlmodel → .mlmodelc
    }
    let model = try MLModel(contentsOf: compiled)
    guard let (name, desc) = model.modelDescription.inputDescriptionsByName
            .first(where: { $0.value.imageConstraint != nil }),
          let img = desc.imageConstraint else {
        throw NSError(domain: "FaceEval", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: "У моделі немає image-входу"])
    }
    return (model, name, CGSize(width: img.pixelsWide, height: img.pixelsHigh))
}

let ciContext = CIContext()
let (model, inputName, inputSize) = try loadModel(modelPath)
print("→ Модель: вхід \"\(inputName)\" \(Int(inputSize.width))×\(Int(inputSize.height))")

// MARK: - Завантаження зображення → CGImage

func loadCGImage(_ path: String) -> CGImage? {
    guard let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil),
          let img = CGImageSourceCreateImageAtIndex(src, 0, nil) else { return nil }
    return img
}

// MARK: - Вирівнювання обличчя (дослівно як FaceMatcher.alignedFace)

func averagePoint(_ points: [CGPoint]) -> CGPoint {
    guard !points.isEmpty else { return .zero }
    let sum = points.reduce(CGPoint.zero) { CGPoint(x: $0.x + $1.x, y: $0.y + $1.y) }
    return CGPoint(x: sum.x / CGFloat(points.count), y: sum.y / CGFloat(points.count))
}

func rotate(_ cgImage: CGImage, by angle: CGFloat) -> CGImage? {
    let ci = CIImage(cgImage: cgImage).transformed(by: CGAffineTransform(rotationAngle: angle))
    return ciContext.createCGImage(ci, from: ci.extent)
}

func crop(_ cgImage: CGImage, normalizedBox box: CGRect) -> CGImage? {
    let w = CGFloat(cgImage.width), h = CGFloat(cgImage.height)
    let padX = box.width * 0.3, padY = box.height * 0.3
    let rect = CGRect(
        x: max(0, (box.minX - padX) * w),
        y: max(0, (1 - box.maxY - padY) * h),
        width: min(w, (box.width + padX * 2) * w),
        height: min(h, (box.height + padY * 2) * h)
    ).integral
    return cgImage.cropping(to: rect)
}

func alignedFace(_ cgImage: CGImage) -> CGImage? {
    let landmarks = VNDetectFaceLandmarksRequest()
    try? VNImageRequestHandler(cgImage: cgImage, options: [:]).perform([landmarks])
    guard let face = (landmarks.results ?? []).first else { return nil }

    var rotated = cgImage
    var faceBox = face.boundingBox
    if let lm = face.landmarks, let left = lm.leftEye, let right = lm.rightEye {
        let l = averagePoint(left.normalizedPoints), r = averagePoint(right.normalizedPoints)
        let lx = faceBox.minX + l.x * faceBox.width, ly = faceBox.minY + l.y * faceBox.height
        let rx = faceBox.minX + r.x * faceBox.width, ry = faceBox.minY + r.y * faceBox.height
        let angle = atan2(ry - ly, rx - lx)
        if abs(angle) > .pi / 60, let rot = rotate(cgImage, by: -angle) {
            rotated = rot
            let redetect = VNDetectFaceRectanglesRequest()
            try? VNImageRequestHandler(cgImage: rotated, options: [:]).perform([redetect])
            if let nf = (redetect.results ?? []).first { faceBox = nf.boundingBox }
        }
    }
    return crop(rotated, normalizedBox: faceBox)
}

// MARK: - Ембеддинг (як FaceEmbedder)

func makePixelBuffer(_ cgImage: CGImage, size: CGSize) -> CVPixelBuffer? {
    var buffer: CVPixelBuffer?
    let attrs: [CFString: Any] = [kCVPixelBufferCGImageCompatibilityKey: true,
                                  kCVPixelBufferCGBitmapContextCompatibilityKey: true]
    CVPixelBufferCreate(kCFAllocatorDefault, Int(size.width), Int(size.height),
                        kCVPixelFormatType_32BGRA, attrs as CFDictionary, &buffer)
    guard let buffer else { return nil }
    let ci = CIImage(cgImage: cgImage)
    let scaled = ci.transformed(by: CGAffineTransform(scaleX: size.width / CGFloat(cgImage.width),
                                                      y: size.height / CGFloat(cgImage.height)))
    ciContext.render(scaled, to: buffer)
    return buffer
}

func embedding(_ face: CGImage) -> [Float]? {
    guard let pb = makePixelBuffer(face, size: inputSize),
          let input = try? MLDictionaryFeatureProvider(
            dictionary: [inputName: MLFeatureValue(pixelBuffer: pb)]),
          let out = try? model.prediction(from: input),
          let fn = out.featureNames.first,
          let arr = out.featureValue(for: fn)?.multiArrayValue else { return nil }
    var v = [Float](repeating: 0, count: arr.count)
    for i in 0..<arr.count { v[i] = arr[i].floatValue }
    let norm = sqrt(v.reduce(0) { $0 + $1 * $1 })
    guard norm > 0 else { return nil }
    return v.map { $0 / norm }
}

func cosine(_ a: [Float], _ b: [Float]) -> Float {
    guard a.count == b.count, !a.isEmpty else { return 0 }
    return zip(a, b).reduce(0) { $0 + $1.0 * $1.1 }
}

// Кеш ембеддингів за шляхом (одне зображення трапляється в кількох парах)
var cache: [String: [Float]] = [:]
func embed(path: String) -> [Float]? {
    if let e = cache[path] { return e }
    guard let img = loadCGImage(path), let face = alignedFace(img), let e = embedding(face)
    else { cache[path] = []; return nil }
    cache[path] = e
    return e
}

// MARK: - LFW pairs.txt

func lfwImagePath(_ name: String, _ idx: Int) -> String {
    let file = String(format: "%@_%04d.jpg", name, idx)
    return "\(lfwDir)/\(name)/\(file)"
}

guard let pairsRaw = try? String(contentsOfFile: pairsPath, encoding: .utf8) else {
    print("✗ Не читається \(pairsPath)"); exit(1)
}
var lines = pairsRaw.split(separator: "\n").map(String.init)
if let first = lines.first, first.split(separator: "\t").count == 2 { lines.removeFirst() } // заголовок

// MARK: - Прогін

struct Sample { let score: Float; let genuine: Bool }
var samples: [Sample] = []
var faceErrors = 0, done = 0

for line in lines {
    let f = line.split(separator: "\t").map(String.init)
    var p1: String?, p2: String?, genuine = false
    if f.count == 3 {            // matched: name idx1 idx2
        p1 = lfwImagePath(f[0], Int(f[1]) ?? -1); p2 = lfwImagePath(f[0], Int(f[2]) ?? -1); genuine = true
    } else if f.count == 4 {     // mismatched: name1 idx1 name2 idx2
        p1 = lfwImagePath(f[0], Int(f[1]) ?? -1); p2 = lfwImagePath(f[2], Int(f[3]) ?? -1); genuine = false
    } else { continue }

    guard let a = embed(path: p1!), !a.isEmpty, let b = embed(path: p2!), !b.isEmpty else {
        faceErrors += 1; continue
    }
    samples.append(Sample(score: cosine(a, b), genuine: genuine))
    done += 1
    if done % 500 == 0 { FileHandle.standardError.write("… \(done) пар\n".data(using: .utf8)!) }
}

// MARK: - Метрики

let genuine = samples.filter { $0.genuine }.map { $0.score }
let impostor = samples.filter { !$0.genuine }.map { $0.score }
guard !genuine.isEmpty, !impostor.isEmpty else {
    print("✗ Замало валідних пар (genuine=\(genuine.count), impostor=\(impostor.count), face-errors=\(faceErrors))")
    exit(1)
}

func farFrr(at t: Float) -> (far: Double, frr: Double) {
    let far = Double(impostor.filter { $0 >= t }.count) / Double(impostor.count)   // impostor прийнято
    let frr = Double(genuine.filter { $0 < t }.count) / Double(genuine.count)       // genuine відхилено
    return (far, frr)
}

// EER + ROC свіп: EER — точка, де FAR і FRR найближчі (беремо їх max).
var eer = 1.0, eerT: Float = 0, bestGap = Double.greatestFiniteMagnitude
var roc: [(t: Float, far: Double, tar: Double)] = []
var t: Float = -1.0
while t <= 1.0001 {
    let (far, frr) = farFrr(at: t)
    roc.append((t, far, 1 - frr))
    let gap = abs(far - frr)
    if gap < bestGap { bestGap = gap; eer = max(far, frr); eerT = t }
    t += 0.01
}

// AUC (трапеції по TAR vs FAR, впорядкованих за FAR)
let rocSorted = roc.sorted { $0.far < $1.far }
var auc = 0.0
for i in 1..<rocSorted.count {
    let dx = rocSorted[i].far - rocSorted[i-1].far
    auc += dx * (rocSorted[i].tar + rocSorted[i-1].tar) / 2
}

let (farOp, frrOp) = farFrr(at: matchThreshold)
print("""

═══ FAR/FRR (LFW) ═══
Валідних пар: genuine=\(genuine.count), impostor=\(impostor.count); face-detect errors=\(faceErrors)
Робочий поріг (cosine ≥ \(matchThreshold)):
   FAR = \(String(format: "%.4f", farOp))  (impostor прийнято помилково)
   FRR = \(String(format: "%.4f", frrOp))  (genuine відхилено помилково)
EER ≈ \(String(format: "%.4f", eer)) при порозі \(String(format: "%.3f", eerT))
AUC ≈ \(String(format: "%.4f", auc))
""")

if let rocPath {
    var csv = "threshold,FAR,TAR\n"
    for r in roc { csv += "\(r.t),\(r.far),\(r.tar)\n" }
    try? csv.write(toFile: rocPath, atomically: true, encoding: .utf8)
    print("ROC → \(rocPath)")
}
