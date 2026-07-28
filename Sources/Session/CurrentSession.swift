import Foundation
import Combine
import UIKit

/// Privacy-first: персональные данные документа НИКОГДА не сохраняются.
/// После верификации остаётся только статус Verified ID.
/// Ник и фото — добровольные, задаются пользователем отдельно.
final class CurrentSession: ObservableObject {
    static let shared = CurrentSession()

    let currentUserId: UUID

    @Published var roles: [UserRole]

    /// Публичный ник (не имя из документа!) — выбирает сам пользователь.
    @Published var displayName: String = "Учасник"

    /// Аватар — выбирает сам пользователь (не фото из документа!).
    @Published var avatar: UIImage?

    /// Verified ID. ДЖЕРЕЛО ІСТИНИ — БАЗА (contributors.verified).
    /// Локальний прапорець — лише кеш підтвердженого базою статусу.
    /// Без входу в акаунт verified бути НЕ МОЖЕ.
    @Published private(set) var isVerified: Bool = false

    /// Чи ПІДТВЕРДЖЕНО статус бекендом у цій сесії. Кеш «підтверджує»,
    /// але НЕ «призначає» Verified ID: на старті беремо false і не
    /// показуємо ні бейдж, ні банер «пройди верифікацію», доки бекенд
    /// не відповів (інакше відкликаний акаунт світився б зі старого
    /// кешу, а живий — блимав би банером). Оновлюється у apply().
    @Published private(set) var statusConfirmed: Bool = false

    /// Координатор. ДЖЕРЕЛО ІСТИНИ — БАЗА (contributors.is_coordinator).
    /// Призначає система; з застосунку роль узяти неможливо.
    @Published private(set) var isCoordinator: Bool = false

    /// ISO-код страны нахождения (наприклад "SE") — для пространства
    /// спільноти. Только код страны, без координат.
    @Published var countryCode: String?

    /// contributor_id из бэкенда (после входа). nil — демо-режим.
    @Published var backendContributorId: String?

    /// Ошибка синхронизации статуса верификации с базой (если была)
    @Published var verifySyncError: String?

    /// Помилка збереження профілю (ник / фото) у базі
    @Published var profileSyncError: String?

    /// ID для запросов: боевой contributor_id, иначе локальный (демо)
    var apiContributorId: String {
        backendContributorId ?? AuthStore.contributorId ?? currentUserId.uuidString
    }

    private let nicknameKey = "ostrov.nickname"
    private let verifiedKey = "ostrov.verified"
    private let coordinatorKey = "ostrov.coordinator"
    private let countryKey = "ostrov.country"

    func setCountry(_ code: String) {
        countryCode = code
        UserDefaults.standard.set(code, forKey: countryKey)
    }

    private var avatarURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("avatar.jpg")
    }

    /// Профіль (ник + фото). ДЖЕРЕЛО ІСТИНИ — БАЗА:
    /// те саме імʼя і фото видно і в застосунку, і на ostrovua.online.
    /// Локально тримаємо лише кеш, щоб малювати миттєво.
    func saveProfile(nickname: String?, avatar: UIImage?) {
        if let nickname, nickname.trimmingCharacters(in: .whitespaces).isEmpty == false {
            displayName = nickname.trimmingCharacters(in: .whitespaces)
            UserDefaults.standard.set(displayName, forKey: nicknameKey)
        }

        if let avatar {
            self.avatar = avatar
            if let data = avatar.jpegData(compressionQuality: 0.85) {
                try? data.write(to: avatarURL)
            }
        }

        guard AuthStore.isLoggedIn else { return }

        let name = displayName
        let photo = avatar.flatMap(Self.dataURL)

        Task { @MainActor in
            do {
                if let nickname, nickname.trimmingCharacters(in: .whitespaces).isEmpty == false {
                    try await VerifyService.updateName(name)
                }
                if let photo {
                    try await VerifyService.updatePhoto(photo)
                }
                profileSyncError = nil
            } catch {
                profileSyncError = AppErrors.text(error)
            }
        }
    }

    /// Фото → data-URL (як у веб-версії): 512 px, ~0.6 якості
    nonisolated private static func dataURL(_ image: UIImage) -> String? {
        let side: CGFloat = 512
        let scale = min(side / image.size.width, side / image.size.height, 1)
        let size = CGSize(width: image.size.width * scale, height: image.size.height * scale)

        let renderer = UIGraphicsImageRenderer(size: size)
        let resized = renderer.image { _ in
            image.draw(in: CGRect(origin: .zero, size: size))
        }

        guard let data = resized.jpegData(compressionQuality: 0.6) else { return nil }
        return "data:image/jpeg;base64," + data.base64EncodedString()
    }

    nonisolated private static func image(from dataURL: String) -> UIImage? {
        guard dataURL.hasPrefix("data:"),
              let comma = dataURL.firstIndex(of: ","),
              let data = Data(base64Encoded: String(dataURL[dataURL.index(after: comma)...]))
        else { return nil }
        return UIImage(data: data)
    }

    /// Данные пользователя из бэкенда (после /auth/login|register)
    func applyBackendUser(id: String, name: String) {
        backendContributorId = id
        if name.isEmpty == false, UserDefaults.standard.string(forKey: nicknameKey) == nil {
            displayName = name
        }
    }

    /// Вихід: токен, contributor_id, Verified ID і роль координатора скидаються
    func logout() {
        // Спершу знімаємо пристрій із push — щоб чужі сповіщення
        // не прилітали на цей телефон після зміни акаунта.
        // PushService живе на головному акторі, тому через Task.
        Task { @MainActor in
            PushService.shared.unregisterFromServer()
        }

        AuthService.logout()
        backendContributorId = nil
        isVerified = false
        isCoordinator = false
        UserDefaults.standard.set(false, forKey: verifiedKey)
        UserDefaults.standard.set(false, forKey: coordinatorKey)
        applyRoles()
    }

    /// Верифікація пройдена на пристрої. Статус стає Verified ID ЛИШЕ
    /// після підтвердження базою — локально нічого не «вмикається».
    /// У legacy review-flow персональні дані не передаються. Production v6
    /// окремо надсилає їх лише self-hosted одноразовому verifier у RAM.
    ///
    /// Повертає true, лише якщо база реально записала verified = true.
    /// Застосунок не має показувати «Verified ID», доки цього не сталося,
    /// інакше людина побачить успіх, а на наступному вході — знову
    /// прохання верифікуватися.
    @MainActor
    @discardableResult
    func markVerified(evidence: VerificationEvidence) async -> Bool {
        guard AuthStore.isLoggedIn else {
            // Демо-режим: верифікація без акаунта не дає Verified ID
            verifySyncError = trs("Спочатку увійди в акаунт — статус зберігається в базі.")
            return false
        }

        do {
            try await VerifyService.approve(evidence: evidence)

            // Джерело істини — база. Перечитуємо, а не віримо собі.
            let status = try await VerifyService.fetchMyStatus()
            apply(status)

            guard isVerified else {
                verifySyncError = AppErrors.text(APIError.server(trs("База не підтвердила статус.")))
                return false
            }

            verifySyncError = nil
            return true
        } catch {
            verifySyncError = AppErrors.text(error)
            return false
        }
    }

    /// Записуємо те, що віддала база
    @MainActor
    private func apply(_ status: (verified: Bool, name: String, isCoordinator: Bool, photoURL: String?)) {
        statusConfirmed = true          // бекенд відповів — статус визначено
        isVerified = status.verified
        UserDefaults.standard.set(status.verified, forKey: verifiedKey)

        isCoordinator = status.isCoordinator
        UserDefaults.standard.set(status.isCoordinator, forKey: coordinatorKey)
        applyRoles()

        // Профіль — це те, що в базі. Той самий ник і фото,
        // що бачать інші учасники й сайт.
        if status.name.isEmpty == false {
            displayName = status.name
            UserDefaults.standard.set(status.name, forKey: nicknameKey)
        }

        if let photo = status.photoURL, let image = Self.image(from: photo) {
            avatar = image
            if let data = image.jpegData(compressionQuality: 0.85) {
                try? data.write(to: avatarURL)
            }
        }
    }

    /// Підтягує статус верифікації та імʼя з бази (єдине джерело істини)
    func refreshFromBackend() {
        guard AuthStore.isLoggedIn else {
            // Немає входу — немає ні Verified ID, ні ролі координатора
            isVerified = false
            isCoordinator = false
            statusConfirmed = true          // визначено: без входу — не verified
            UserDefaults.standard.set(false, forKey: verifiedKey)
            UserDefaults.standard.set(false, forKey: coordinatorKey)
            applyRoles()
            return
        }

        Task { @MainActor in
            if let status = try? await VerifyService.fetchMyStatus() {
                apply(status)
            }
        }
    }

    /// Ролі рахуються з підтверджених базою прапорців — жодного локального «призначення»
    private func applyRoles() {
        var next: [UserRole] = [.participant]
        if isCoordinator { next.append(.projectCoordinator) }
        roles = next
    }

    private func restoreProfile() {
        if let saved = UserDefaults.standard.string(forKey: nicknameKey), saved.isEmpty == false {
            displayName = saved
        }
        // Verified ID і роль НЕ беремо з кешу — їх «призначає» лише
        // бекенд (refreshFromBackend/apply). До підтвердження — false,
        // тож відкликаний статус не «світиться» зі старого кешу.
        isVerified = false
        isCoordinator = false
        statusConfirmed = false
        countryCode = UserDefaults.standard.string(forKey: countryKey)
        if let data = try? Data(contentsOf: avatarURL) {
            avatar = UIImage(data: data)
        }
    }

    private init() {
        self.currentUserId = MockCurrentUser.participantId

        // Ролі більше не роздаються локально: базовий рівень — учасник,
        // координатора додає лише база (is_coordinator).
        self.roles = [.participant]

        restoreProfile()
        applyRoles()
        backendContributorId = AuthStore.contributorId
    }

    func hasRole(_ role: UserRole) -> Bool {
        roles.contains(role)
    }

    func hasAnyRole(_ requiredRoles: [UserRole]) -> Bool {
        requiredRoles.contains { role in
            roles.contains(role)
        }
    }

    func toggleRole(_ role: UserRole) {
        if roles.contains(role) {
            roles.removeAll { currentRole in
                currentRole == role
            }
        } else {
            roles.append(role)
        }
    }

    func setRoles(_ roles: [UserRole]) {
        self.roles = roles
    }
}
