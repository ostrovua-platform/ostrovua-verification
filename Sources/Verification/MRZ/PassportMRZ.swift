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
        isValidCalendarDate(dateOfBirth) &&
        isValidCalendarDate(dateOfExpiry) &&
        isNotExpired(dateOfExpiry)
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

    /// РЕАЛЬНА перевірка календарної дати через Calendar: 31 лютого,
    /// 30 лютого, 31 квітня тощо відхиляються (раніше приймалось будь-що
    /// з mm 1–12, dd 1–31).
    private func isValidCalendarDate(_ value: String) -> Bool {
        Self.date(fromYYMMDD: value) != nil
    }

    /// Документ не має бути простроченим на момент перевірки.
    private func isNotExpired(_ expiry: String) -> Bool {
        guard let date = Self.date(fromYYMMDD: expiry, isExpiry: true) else { return false }
        return date >= Calendar(identifier: .gregorian).startOfDay(for: Date())
    }

    /// YYMMDD → Date з суворою валідацією (без «переповнення» на наступний
    /// місяць). Для терміну дії 2-значний рік трактуємо як 20YY.
    static func date(fromYYMMDD value: String, isExpiry: Bool = false) -> Date? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count == 6, trimmed.allSatisfy(\.isNumber),
              let yy = Int(trimmed.prefix(2)),
              let mm = Int(trimmed.dropFirst(2).prefix(2)),
              let dd = Int(trimmed.dropFirst(4)) else { return nil }

        // Рік: термін дії — завжди 20YY; дата народження — 19YY/20YY
        // (майбутнє неможливе → якщо 20YY у майбутньому, це 19YY).
        var year = 2000 + yy
        if isExpiry == false, year > Calendar.current.component(.year, from: Date()) {
            year -= 100
        }

        var components = DateComponents()
        components.year = year
        components.month = mm
        components.day = dd

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        // isValidDate вимагає, щоб компоненти існували в календарі
        // (31 лютого не існує — поверне false).
        guard calendar.date(from: components) != nil,
              calendar.date(components, matchesComponents: DateComponents(year: year, month: mm, day: dd)) != false
        else { return nil }

        // Додаткова строга перевірка: збираємо дату й розбираємо назад
        guard let date = calendar.date(from: components) else { return nil }
        let back = calendar.dateComponents([.year, .month, .day], from: date)
        guard back.year == year, back.month == mm, back.day == dd else { return nil }
        return date
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

        // TD3 — рівно 44 символи. Раніше приймалось >= 28: обрізаний
        // рядок проходив, композитна чек-цифра не перевірялась зовсім.
        guard line.count == 44 else {
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
        let compositeCheck = chars[43]

        // Композитна чек-цифра TD3: над номером+чек, датою нар.+чек,
        // терміном+чек і персональним номером(28–42)+чек(42).
        let composite = docNumberRaw + String(docCheck)
            + birth + String(birthCheck)
            + expiry + String(expiryCheck)
            + String(chars[28..<43])

        guard
            verifyCheckDigit(docNumberRaw, expected: docCheck),
            verifyCheckDigit(birth, expected: birthCheck),
            verifyCheckDigit(expiry, expected: expiryCheck),
            verifyCheckDigit(composite, expected: compositeCheck)
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
