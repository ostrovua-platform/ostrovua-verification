import Foundation

/// MRZ-данные для BAC-ключа NFC-чипа (ICAO 9303, TD3).
struct PassportMRZ: Equatable {
    var documentNumber: String = ""
    var dateOfBirth: String = ""   // YYMMDD
    var dateOfExpiry: String = ""  // YYMMDD

    /// Гражданство из MRZ (позиции 10–12 второй строки), например «UKR».
    /// Пустое — при ручном вводе полей.
    var nationality: String = ""

    var isValid: Bool {
        normalizedDocumentNumber.isEmpty == false &&
        isValidDate(dateOfBirth) &&
        isValidDate(dateOfExpiry)
    }

    /// Пропускаем только документы України:
    /// - если гражданство известно из MRZ — строго «UKR»;
    /// - при ручном вводе — украинский формат номера:
    ///   закордонний паспорт (2 літери + 6 цифр) или ID-картка (9 цифр).
    var isUkrainian: Bool {
        if nationality.isEmpty == false {
            return nationality == "UKR"
        }

        let doc = normalizedDocumentNumber
        let passportFormat = doc.range(of: "^[A-Z]{2}[0-9]{6}$", options: .regularExpression) != nil
        let idCardFormat = doc.range(of: "^[0-9]{9}$", options: .regularExpression) != nil
        return passportFormat || idCardFormat
    }

    var normalizedDocumentNumber: String {
        documentNumber
            .uppercased()
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "<", with: "")
    }

    private func isValidDate(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count == 6, trimmed.allSatisfy(\.isNumber) else {
            return false
        }

        let mm = Int(trimmed.dropFirst(2).prefix(2)) ?? 0
        let dd = Int(trimmed.dropFirst(4)) ?? 0
        return (1...12).contains(mm) && (1...31).contains(dd)
    }

    /// MRZ-ключ для BAC/PACE (NFCPassportReader):
    /// номер (9 знаков, добитый '<') + чек-цифра + дата рождения + чек + дата окончания + чек.
    var bacKey: String {
        let doc = normalizedDocumentNumber.padding(toLength: 9, withPad: "<", startingAt: 0)
        let dob = dateOfBirth.trimmingCharacters(in: .whitespacesAndNewlines)
        let exp = dateOfExpiry.trimmingCharacters(in: .whitespacesAndNewlines)

        return doc + String(Self.computeCheckDigit(doc))
            + dob + String(Self.computeCheckDigit(dob))
            + exp + String(Self.computeCheckDigit(exp))
    }

    /// Чек-цифра ICAO 9303 (веса 7-3-1).
    static func computeCheckDigit(_ value: String) -> Int {
        let weights = [7, 3, 1]
        var sum = 0

        for (index, char) in value.enumerated() {
            let charValue: Int
            if char.isNumber {
                charValue = char.wholeNumberValue ?? 0
            } else if char.isLetter, let ascii = char.asciiValue {
                charValue = Int(ascii) - 55
            } else {
                charValue = 0
            }
            sum += charValue * weights[index % 3]
        }

        return sum % 10
    }

    // MARK: - Санитизация ввода

    /// Номер документа: только буквы/цифры, uppercase, максимум 9 символов.
    static func sanitizeDocumentNumber(_ raw: String) -> String {
        String(
            raw.uppercased()
                .filter { $0.isLetter || $0.isNumber }
                .prefix(9)
        )
    }

    /// Дата MRZ: только цифры, максимум 6 (YYMMDD).
    static func sanitizeDate(_ raw: String) -> String {
        String(raw.filter(\.isNumber).prefix(6))
    }

    // MARK: - Парсинг второй строки MRZ (TD3, 44 символа)

    /// Разбирает вторую строку MRZ паспорта:
    /// позиции 0–8 номер документа (чек-цифра 9), 13–18 дата рождения (чек 19),
    /// 21–26 дата окончания (чек 27). Чек-цифры проверяются по схеме 7-3-1.
    static func parse(mrzLine: String) -> PassportMRZ? {
        let line = mrzLine
            .uppercased()
            .replacingOccurrences(of: " ", with: "")

        guard line.count >= 28 else {
            return nil
        }

        let chars = Array(line)

        let docNumberRaw = String(chars[0..<9])
        let docCheck = chars[9]
        let nationality = String(chars[10..<13])
        let birth = String(chars[13..<19])
        let birthCheck = chars[19]
        let expiry = String(chars[21..<27])
        let expiryCheck = chars[27]

        guard
            verifyCheckDigit(docNumberRaw, expected: docCheck),
            verifyCheckDigit(birth, expected: birthCheck),
            verifyCheckDigit(expiry, expected: expiryCheck)
        else {
            return nil
        }

        var mrz = PassportMRZ()
        mrz.documentNumber = docNumberRaw.replacingOccurrences(of: "<", with: "")
        mrz.dateOfBirth = birth
        mrz.dateOfExpiry = expiry
        mrz.nationality = nationality.replacingOccurrences(of: "<", with: "")

        return mrz.isValid ? mrz : nil
    }

    /// Проверка чек-цифры ICAO 9303: веса 7-3-1, A=10…Z=35, '<'=0.
    private static func verifyCheckDigit(_ value: String, expected: Character) -> Bool {
        guard let expectedDigit = expected.wholeNumberValue else {
            return false
        }

        return computeCheckDigit(value) == expectedDigit
    }
}
