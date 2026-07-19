import Foundation

enum PassportDataMatcher {
    static func match(
        profile: VerificationProfileDraft,
        mrz: PassportMRZ,
        passport: PassportData
    ) -> PassportMatchResult {
        var issues: [String] = []

        let profileDocumentNumber = normalize(profile.documentNumber)
        let mrzDocumentNumber = normalize(mrz.documentNumber)
        let passportDocumentNumber = normalize(passport.documentNumber)

        if profileDocumentNumber.isEmpty == false &&
            passportDocumentNumber.isEmpty == false &&
            profileDocumentNumber != passportDocumentNumber {
            issues.append("Номер документа в профілі не збігається з NFC-даними.")
        }

        if mrzDocumentNumber.isEmpty == false &&
            passportDocumentNumber.isEmpty == false &&
            mrzDocumentNumber != passportDocumentNumber {
            issues.append("Номер документа в MRZ не збігається з NFC-даними.")
        }

        let profileBirthDate = normalizeFlexibleDate(profile.dateOfBirth)
        let mrzBirthDate = normalizeFlexibleDate(mrz.dateOfBirth)
        let passportBirthDate = normalizeFlexibleDate(passport.dateOfBirth)

        if profileBirthDate.isEmpty == false &&
            mrzBirthDate.isEmpty == false &&
            profileBirthDate != mrzBirthDate {
            issues.append("Дата народження в профілі не збігається з MRZ.")
        }

        if passportBirthDate.isEmpty == false &&
            mrzBirthDate.isEmpty == false &&
            passportBirthDate != mrzBirthDate {
            issues.append("Дата народження в NFC-даних не збігається з MRZ.")
        }

        let mrzExpiryDate = normalizeFlexibleDate(mrz.dateOfExpiry)
        let passportExpiryDate = normalizeFlexibleDate(passport.dateOfExpiry)

        if mrzExpiryDate.isEmpty == false &&
            passportExpiryDate.isEmpty == false &&
            mrzExpiryDate != passportExpiryDate {
            issues.append("Дата завершення документа не збігається з NFC-даними.")
        }

        if issues.isEmpty {
            return .matched
        }

        return .needsManualReview(issues)
    }

    private static func normalize(_ value: String) -> String {
        value
            .uppercased()
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "<", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func normalizeFlexibleDate(_ value: String) -> String {
        let clean = value
            .replacingOccurrences(of: ".", with: "")
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: "/", with: "")
            .replacingOccurrences(of: " ", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard clean.isEmpty == false else {
            return ""
        }

        // YYYYMMDD → YYMMDD
        if clean.count == 8 {
            let firstFour = String(clean.prefix(4))

            if firstFour.hasPrefix("19") || firstFour.hasPrefix("20") {
                let year = clean.prefix(4)
                let month = clean.dropFirst(4).prefix(2)
                let day = clean.suffix(2)

                return "\(year.suffix(2))\(month)\(day)"
            }

            // DDMMYYYY → YYMMDD
            let day = clean.prefix(2)
            let month = clean.dropFirst(2).prefix(2)
            let year = clean.suffix(4)

            return "\(year.suffix(2))\(month)\(day)"
        }

        if clean.count == 6 {
            let firstTwo = String(clean.prefix(2))
            let middleTwo = String(clean.dropFirst(2).prefix(2))
            let lastTwo = String(clean.suffix(2))

            let yyMMddMonth = Int(middleTwo) ?? 99
            let yyMMddDay = Int(lastTwo) ?? 99

            // Уже YYMMDD
            if yyMMddMonth >= 1 &&
                yyMMddMonth <= 12 &&
                yyMMddDay >= 1 &&
                yyMMddDay <= 31 {
                return clean
            }

            // DDMMYY → YYMMDD
            let day = firstTwo
            let month = middleTwo
            let year = lastTwo

            return "\(year)\(month)\(day)"
        }

        return clean
    }
}
