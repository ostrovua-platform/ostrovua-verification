import Foundation

enum FaceLivenessResult: Equatable {
    case notStarted
    case requestingPermission
    case startingCamera
    case searchingFace
    case faceDetected
    case livenessPassed(String)
    case failed(String)

    /// Камера сейчас работает — показываем живое превью.
    var isCameraActive: Bool {
        switch self {
        case .startingCamera, .searchingFace, .faceDetected:
            return true
        default:
            return false
        }
    }

    var title: String {
        switch self {
        case .notStarted:
            return trs("Не розпочато")

        case .requestingPermission:
            return trs("Запит доступу")

        case .startingCamera:
            return trs("Запуск камери")

        case .searchingFace:
            return trs("Пошук обличчя")

        case .faceDetected:
            return trs("Обличчя знайдено")

        case .livenessPassed:
            return trs("Живість підтверджено")

        case .failed:
            return trs("Помилка перевірки")
        }
    }

    var message: String {
        switch self {
        case .notStarted:
            return trs("Камера потрібна для перевірки живої присутності.")

        case .requestingPermission:
            return trs("Дозволь доступ до камери для продовження.")

        case .startingCamera:
            return trs("Камера запускається.")

        case .searchingFace:
            return trs("Тримай обличчя в кадрі та не закривай камеру.")

        case .faceDetected:
            return trs("Обличчя знайдено. Тримай iPhone стабільно.")

        case .livenessPassed(let message):
            return message

        case .failed(let message):
            return message
        }
    }
}
