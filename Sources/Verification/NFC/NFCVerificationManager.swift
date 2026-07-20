import Foundation
import Combine
import UIKit
import CryptoKit
import CommonCrypto

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

    /// EF.SOD — підписаний державою обʼєкт безпеки чипа (хеші DG +
    /// сертифікат + підпис, БЕЗ персональних полів). Іде на сервер
    /// для Passive Authentication. На симуляторі — nil.
    private(set) var chipSOD: Data?

    /// Хеші прочитаних груп даних ("dg1"/"dg2" → алгоритм → hex).
    /// Сервер звіряє їх з хешами, підписаними державою в SOD.
    private(set) var dgHashes: [String: [String: String]] = [:]

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
        chipSOD = nil
        dgHashes = [:]
    }

    /// Усі дозволені ICAO алгоритми одним махом: сервер порівнює тим,
    /// який записано в SOD (український — SHA-256, але не вгадуємо).
    /// SHA-224 нема в CryptoKit — рахуємо через CommonCrypto.
    private static func allHashes(_ data: Data) -> [String: String] {
        [
            "sha1": Insecure.SHA1.hash(data: data).map { String(format: "%02x", $0) }.joined(),
            "sha224": sha224Hex(data),
            "sha256": SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
            "sha384": SHA384.hash(data: data).map { String(format: "%02x", $0) }.joined(),
            "sha512": SHA512.hash(data: data).map { String(format: "%02x", $0) }.joined(),
        ]
    }

    private static func sha224Hex(_ data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            _ = CC_SHA224(buffer.baseAddress, CC_LONG(buffer.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Реальное чтение (устройство)

    #if canImport(NFCPassportReader) && !targetEnvironment(simulator)
    private func readChip(mrz: PassportMRZ, completion: @escaping (PassportData?) -> Void) {
        Task { @MainActor in
            do {
                let reader = PassportReader()
                let passport = try await reader.readPassport(
                    mrzKey: mrz.bacKey,
                    tags: [.COM, .SOD, .DG1, .DG2],
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

                // Бізнес-правило: приймаємо лише УКРАЇНСЬКИЙ ДОКУМЕНТ
                // (issuing == UKR). Раніше умова була `issuing || nationality`,
                // тобто проходив і чужий документ українця — це не те, що
                // стверджував коментар.
                //
                // ⚠️ ОБМЕЖЕННЯ: ці поля читаються з чипа, але їхня
                // ПІДЛИННІСТЬ поки не перевірена криптографічно
                // (Passive Authentication — server-side, у планах).
                // Тобто клонований/підроблений чип тут ще не відсіється.
                guard issuing == "UKR" else {
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

                // SOD + хеші DG1/DG2 — для серверної Passive Authentication.
                // FAIL-CLOSED: без SOD сервер не зможе довести справжність
                // чипа, тож без нього далі не пускаємо (SOD — обовʼязковий
                // файл ICAO 9303; його відсутність = недочитаний чип).
                guard
                    let sodGroup = passport.getDataGroup(.SOD),
                    let dg1Group = passport.getDataGroup(.DG1),
                    let dg2Group = passport.getDataGroup(.DG2)
                else {
                    self.chipPhoto = nil
                    self.result = .failed(
                        "Не вдалося зчитати обʼєкт безпеки чипа (SOD). Тримай документ нерухомо і спробуй ще раз. (E-405)"
                    )
                    completion(nil)
                    return
                }

                self.chipSOD = Data(sodGroup.data)
                self.dgHashes = [
                    "dg1": Self.allHashes(Data(dg1Group.data)),
                    "dg2": Self.allHashes(Data(dg2Group.data)),
                ]

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
