// swift-tools-version:5.9
import PackageDescription

// Стенд вимірювання FAR/FRR моделі FaceEmbedding на датасеті пар (LFW).
// Використовує ТІЛЬКИ системні фреймворки (Vision, CoreML, ImageIO) —
// той самий препроцесинг, що у застосунку (FaceMatcher + FaceEmbedder),
// тож числа відображають РЕАЛЬНИЙ shipped-пайплайн.
// Збірка/запуск — на macOS: `swift run FaceEval --help`.
let package = Package(
    name: "FaceEval",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "FaceEval", path: "Sources/FaceEval")
    ]
)
