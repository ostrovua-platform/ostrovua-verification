import Foundation
import SwiftUI
import Combine

/// Модель верификации по шагам Figma-макета:
/// Крок 1 — згода, Крок 2 — MRZ, Крок 3 — NFC, Крок 4 — face check.
/// Без старой state-machine: шаги переключает View, модель хранит данные
/// и результат чтения. Кнопки блокируются только валидностью полей.
final class VerificationViewModel: ObservableObject {
    @Published var mrz = PassportMRZ()
    @Published var passportData: PassportData?

    /// Полная вторая строка MRZ — можно вставить или отсканировать целиком.
    @Published var mrzLine = ""
    @Published var mrzLineParseFailed = false

    var mrzIsValid: Bool {
        mrz.isValid
    }

    // MARK: - Ввод MRZ (с санитизацией)

    func updateDocumentNumber(_ raw: String) {
        mrz.documentNumber = PassportMRZ.sanitizeDocumentNumber(raw)
    }

    func updateDateOfBirth(_ raw: String) {
        mrz.dateOfBirth = PassportMRZ.sanitizeDate(raw)
    }

    func updateDateOfExpiry(_ raw: String) {
        mrz.dateOfExpiry = PassportMRZ.sanitizeDate(raw)
    }

    /// Разбирает вставленную строку MRZ (TD3) с проверкой чек-цифр ICAO 9303.
    /// При успехе поля заполняются автоматически.
    @discardableResult
    func applyMRZLine(_ raw: String) -> Bool {
        mrzLine = raw

        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= 28 else {
            mrzLineParseFailed = false
            return false
        }

        guard let parsed = PassportMRZ.parse(mrzLine: trimmed) else {
            mrzLineParseFailed = true
            return false
        }

        mrz = parsed
        mrzLineParseFailed = false
        return true
    }

    // MARK: - Результат NFC

    // passportData заполняется данными с чипа в NFCVerificationManager
    // (BAC/PACE → DG1). Проверка «тільки Україна» — там же, по данным чипа.

    func reset() {
        passportData = nil
    }
}
