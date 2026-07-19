import Foundation
import Combine
import UIKit

#if canImport(NFCPassportReader) && !targetEnvironment(simulator)
import NFCPassportReader
#endif

/// Настоящее чтение чипа биометрического документа (ICAO 9303):
/// BAC/PACE-аутентификация по MRZ-ключу → чтение DG1 (данные) и DG2 (фото) →
/// проверка, что документ выдан Україною. Библиотека NFCPassportReader.
final class NFCVerificationManager: NSObject, ObservableObject {
    @Published private(set) var result: NFCVerificationResult = .notStarted

    /// Фото владельца с чипа (DG2) — используется на шаге face check.
    @Published private(set) var chipPhoto: UIImage?

    /// Читает чип. В completion приходит PassportData с данными
    /// с чипа (или nil при ошибке/неукраинском документе).
    func startScan(mrz: PassportMRZ, completion: @escaping (PassportData?) -> Void) {
        result = .scanning

        #if targetEnvironment(simulator)
        runSimulatorMock(mrz: mrz, completion: completion)
        #elseif canImport(NFCPassportReader)
        readChip(mrz: mrz, completion: completion)
        #else
        result = .failed("NFC недоступний на цьому пристрої.")
        completion(nil)
        #endif
    }

    func reset() {
        result = .notStarted
        chipPhoto = nil
    }

    // MARK: - Реальное чтение (устройство)

    #if canImport(NFCPassportReader) && !targetEnvironment(simulator)
    private func readChip(mrz: PassportMRZ, completion: @escaping (PassportData?) -> Void) {
        Task { @MainActor in
            do {
                let reader = PassportReader()
                let passport = try await reader.readPassport(
                    mrzKey: mrz.bacKey,
                    tags: [.COM, .DG1, .DG2],
                    customDisplayMessage: { message in
                        switch message {
                        case .requestPresentPassport:
                            return trs("Піднеси документ до верхньої частини iPhone.")
                        case .authenticatingWithPassport:
                            return trs("Авторизація з документом…")
                        case .readingDataGroupProgress(let dataGroup, let progress):
                            return "Зчитування \(dataGroup)… \(progress)%"
                        case .successfulRead:
                            return trs("Документ успішно зчитано.")
                        case .error:
                            return trs("Помилка зчитування. Спробуй ще раз.")
                        default:
                            return nil
                        }
                    }
                )

                let issuing = passport.issuingAuthority
                    .replacingOccurrences(of: "<", with: "")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                let nationality = passport.nationality
                    .replacingOccurrences(of: "<", with: "")
                    .trimmingCharacters(in: .whitespacesAndNewlines)

                // ВАЖНО: пропускаем только документы України.
                // Данные читаются с самого чипа — их нельзя подделать вводом.
                guard issuing == "UKR" || nationality == "UKR" else {
                    let issuer = issuing.isEmpty ? nationality : issuing
                    self.result = .failed(
                        "Підтримуються лише документи України. Цей документ видано: \(issuer.isEmpty ? "невідомо" : issuer)."
                    )
                    completion(nil)
                    return
                }

                let fullName = [passport.firstName, passport.lastName]
                    .map { $0.replacingOccurrences(of: "<", with: " ").trimmingCharacters(in: .whitespaces) }
                    .filter { $0.isEmpty == false }
                    .joined(separator: " ")

                let data = PassportData(
                    documentNumber: passport.documentNumber.replacingOccurrences(of: "<", with: ""),
                    fullName: fullName,
                    dateOfBirth: passport.dateOfBirth,
                    dateOfExpiry: passport.documentExpiryDate,
                    citizenship: nationality,
                    issuingCountry: issuing
                )

                // Фото владельца из DG2 — для сверки лица на шаге 4
                self.chipPhoto = passport.passportImage

                self.result = .success("Документ України підтверджено: \(fullName.isEmpty ? data.documentNumber : fullName)")
                completion(data)
            } catch {
                self.result = .failed(
                    "Не вдалося зчитати чип. Перевір MRZ-дані та тримай документ нерухомо. (E-402)"
                )
                completion(nil)
            }
        }
    }
    #endif

    // MARK: - Симулятор

    private func runSimulatorMock(mrz: PassportMRZ, completion: @escaping (PassportData?) -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            let data = PassportData(
                documentNumber: mrz.normalizedDocumentNumber,
                fullName: "Demo Користувач",
                dateOfBirth: mrz.dateOfBirth,
                dateOfExpiry: mrz.dateOfExpiry,
                citizenship: "UKR",
                issuingCountry: "UKR"
            )
            self.result = .success("Demo-режим: NFC-документ успішно зчитано.")
            completion(data)
        }
    }
}
