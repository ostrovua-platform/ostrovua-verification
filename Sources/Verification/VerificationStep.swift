import Foundation
import SwiftUI

enum VerificationStep: String, CaseIterable, Identifiable {
    case profile
    case mrz
    case nfc
    case passportMatch
    case camera
    case review
    case completed

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .profile:
            return trs("Профіль")

        case .mrz:
            return trs("MRZ-дані")

        case .nfc:
            return trs("NFC-документ")

        case .passportMatch:
            return trs("Зіставлення")

        case .camera:
            return trs("Камера / LiDAR")

        case .review:
            return trs("Перевірка")

        case .completed:
            return trs("Готово")
        }
    }

    var icon: String {
        switch self {
        case .profile:
            return "person.crop.circle.fill"

        case .mrz:
            return "doc.text.viewfinder"

        case .nfc:
            return "wave.3.right.circle.fill"

        case .passportMatch:
            return "arrow.triangle.2.circlepath"

        case .camera:
            return "camera.viewfinder"

        case .review:
            return "checkmark.seal.fill"

        case .completed:
            return "shield.checkered"
        }
    }
}

enum VerificationStatus {
    case notStarted
    case inProgress
    case verified
    case failed

    var title: String {
        switch self {
        case .notStarted:
            return trs("Не розпочато")

        case .inProgress:
            return trs("В процесі")

        case .verified:
            return trs("Підтверджено")

        case .failed:
            return trs("Потрібна повторна перевірка")
        }
    }

    var tint: Color {
        switch self {
        case .notStarted:
            return Color.white.opacity(0.64)

        case .inProgress:
            return Color.orange

        case .verified:
            return Color.ostrovLime

        case .failed:
            return Color.ostrovCoral
        }
    }
}

struct VerificationProfileDraft {
    var fullName: String = ""
    var dateOfBirth: String = ""
    var citizenship: String = ""
    var documentNumber: String = ""
}
