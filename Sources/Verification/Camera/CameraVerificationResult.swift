import Foundation

enum CameraVerificationResult: Equatable {
    case notStarted
    case requestingPermission
    case scanning
    case success(String)
    case failed(String)

    var title: String {
        switch self {
        case .notStarted:
            return trs("Не розпочато")

        case .requestingPermission:
            return trs("Запит доступу")

        case .scanning:
            return trs("Перевірка камери")

        case .success:
            return trs("Камеру підтверджено")

        case .failed:
            return trs("Помилка камери")
        }
    }

    var message: String {
        switch self {
        case .notStarted:
            return trs("Камера потрібна для перевірки живої присутності.")

        case .requestingPermission:
            return trs("Дозволь доступ до камери для продовження.")

        case .scanning:
            return trs("Тримай iPhone стабільно. Система перевіряє depth / LiDAR.")

        case .success(let message):
            return message

        case .failed(let message):
            return message
        }
    }
}
