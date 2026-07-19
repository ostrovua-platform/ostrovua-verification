import Foundation
import SwiftUI

enum PassportMatchResult: Equatable {
    case notStarted
    case matching
    case matched
    case needsManualReview([String])
    case failed(String)

    var title: String {
        switch self {
        case .notStarted:
            return trs("Не розпочато")

        case .matching:
            return trs("Зіставлення даних")

        case .matched:
            return trs("Дані збігаються")

        case .needsManualReview:
            return trs("Потрібна ручна перевірка")

        case .failed:
            return trs("Помилка зіставлення")
        }
    }

    var message: String {
        switch self {
        case .notStarted:
            return trs("Після NFC система зіставить паспортні дані з профілем.")

        case .matching:
            return trs("Порівнюємо MRZ, профіль і дані документа.")

        case .matched:
            return trs("Дані профілю, MRZ і документа збігаються.")

        case .needsManualReview(let reasons):
            return reasons.joined(separator: "\n")

        case .failed(let message):
            return message
        }
    }

    var tint: Color {
        switch self {
        case .notStarted:
            return Color.white.opacity(0.58)

        case .matching:
            return Color.orange

        case .matched:
            return Color.ostrovLime

        case .needsManualReview:
            return Color.orange

        case .failed:
            return Color.ostrovCoral
        }
    }
}
