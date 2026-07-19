import Foundation

enum NFCVerificationResult: Equatable {
    case notStarted
    case scanning
    case success(String)
    case failed(String)

    var title: String {
        switch self {
        case .notStarted:
            "Не розпочато"

        case .scanning:
            "Сканування NFC"

        case .success:
            "Документ зчитано"

        case .failed:
            "Помилка NFC"
        }
    }

    var message: String {
        switch self {
        case .notStarted:
            "Піднеси документ до верхньої частини iPhone."

        case .scanning:
            "Тримай документ біля iPhone, поки сканування не завершиться."

        case .success(let message):
            message

        case .failed(let message):
            message
        }
    }
}
