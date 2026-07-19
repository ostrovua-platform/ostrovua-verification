import SwiftUI
import PhotosUI

/// Флоу верификации 1-в-1 по Figma «Application ios/NFC V1.0»:
/// Крок 1 — згода → Крок 2 — MRZ → Крок 3 — NFC → Крок 4 — face check → Успіх.
/// Ошибка NFC — отдельный экран с советами. Шаги переключает View,
/// кнопки зависят только от валидности данных — никаких скрытых блокировок.
struct VerificationView: View {
    @ObservedObject var router: AppRouter

    @StateObject private var viewModel = VerificationViewModel()
    @StateObject private var nfcManager = NFCVerificationManager()
    @StateObject private var faceManager = FaceLivenessManager()

    @Environment(\.colorScheme) private var colorScheme

    private enum FlowScreen {
        case consent       // Крок 1 з 4
        case mrz           // Крок 2 з 4
        case nfc           // Крок 3 з 4
        case nfcError
        case face          // Крок 4 з 4
        case success
        case profileSetup  // ник + фото (добровольно)
    }

    @State private var screen: FlowScreen = .consent
    @State private var consentAgreed = false

    @StateObject private var mrzScanner = MRZScannerManager()
    @State private var showManualMRZEntry = false

    @State private var isMatchingFace = false
    @State private var faceMatchError: String?

    /// Статус Verified ID пишеться в базу — чекаємо на відповідь
    @ObservedObject private var session = CurrentSession.shared
    @State private var isSavingStatus = false

    // Профиль (добровольный, задаёт сам пользователь)
    @State private var nickname = ""
    @State private var selectedPhoto: PhotosPickerItem?
    @State private var avatarImage: UIImage?

    private var palette: VerifyPalette {
        VerifyPalette.palette(for: colorScheme)
    }

    var body: some View {
        ZStack {
            VerifyBackground()

            switch screen {
            case .consent:
                consentScreen
            case .mrz:
                mrzScreen
            case .nfc:
                nfcScreen
            case .nfcError:
                nfcErrorScreen
            case .face:
                faceScreen
            case .success:
                successScreen
            case .profileSetup:
                profileSetupScreen
            }
        }
        .statusBarHidden(true)
        .animation(.easeInOut(duration: 0.25), value: screen)
        // Камера/сканери не мають лишатись активними за межами екрана
        .onChange(of: screen) { _, newScreen in
            if newScreen != .face {
                faceManager.stop()
            }
            if newScreen != .mrz {
                mrzScanner.stop()
            }
        }
        .onDisappear {
            faceManager.stop()
            mrzScanner.stop()
            nfcManager.reset()
            wipeSensitiveData()
        }
    }

    // MARK: - Каркас шага (топбар + прогресс + pill «Крок N з 4»)

    private func stepScaffold<Content: View>(
        step: Int,
        onBack: @escaping () -> Void,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            VerifyTopBar()

            VerifyStepProgress(current: step, total: 4)

            HStack(spacing: 12) {
                Button {
                    onBack()
                } label: {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 15, weight: .bold))
                        .foregroundStyle(palette.textPrimary)
                        .frame(width: 36, height: 36)
                        .background(palette.surface, in: Circle())
                }
                .buttonStyle(.plain)

                VerifyStepPill(step: step, total: 4)

                Spacer()
            }

            content()
        }
        .padding(.horizontal, 20)
        .padding(.top, 54)
        .padding(.bottom, 26)
    }

    // MARK: - Крок 1 з 4: згода

    private var consentScreen: some View {
        stepScaffold(step: 1, onBack: { router.openAuth() }) {
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 12) {
                        ConsentRow(
                            title: trs("Читаємо NFC-чип"),
                            subtitle: trs("Ідентифікаційні дані для перевірки"),
                            icon: "wave.3.right"
                        )
                        ConsentRow(
                            title: trs("Зберігаємо статус"),
                            subtitle: trs("У профілі видно Verified ID, не повний документ"),
                            icon: "checkmark.seal.fill",
                            checked: true
                        )
                        ConsentRow(
                            title: trs("Доступ за ролями"),
                            subtitle: trs("Матеріали відкриваються лише за потреби"),
                            icon: "person.2.fill"
                        )
                    }
                    .verifyOliveCard()

                    HStack {
                        Text(trs("Я погоджуюсь з обробкою даних для верифікації"))
                            .font(.inter(13, .semibold))
                            .foregroundStyle(palette.textPrimary)

                        Spacer()

                        Toggle("", isOn: $consentAgreed)
                            .labelsHidden()
                            .tint(palette.lime)
                    }
                    .verifySurfaceCard()

                    Button {
                        screen = .mrz
                    } label: {
                        VerifyPrimaryButtonLabel(
                            title: trs("Погоджуюсь і продовжити"),
                            enabled: consentAgreed
                        )
                    }
                    .buttonStyle(.plain)
                    .disabled(consentAgreed == false)

                    Text(trs("Політика конфіденційності"))
                        .font(.lufga(12, .light))
                        .foregroundStyle(palette.textSecondary)
                        .frame(maxWidth: .infinity)
                }
            }
        }
    }

    // MARK: - Крок 2 з 4: MRZ (сканер камерой, ручной ввод — по кнопке)

    private var mrzScreen: some View {
        stepScaffold(step: 2, onBack: {
            mrzScanner.stop()
            screen = .consent
        }) {
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 14) {
                    Text("Скануй сторінку\nз фото документа")
                        .font(.inter(26, .heavy))
                        .foregroundStyle(palette.textPrimary)

                    Text(trs("Наведись на MRZ-зону — це два рядки внизу сторінки. Вони потрібні для безпечного доступу до NFC-чипа."))
                        .font(.lufga(14, .light))
                        .foregroundStyle(palette.textSecondary)
                        .lineSpacing(3)

                    scannerViewport

                    if viewModel.mrzIsValid {
                        scannedDataCard
                    }

                    // Только документы України
                    if viewModel.mrzIsValid && viewModel.mrz.isUkrainian == false {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.system(size: 16))
                                .foregroundStyle(palette.coral)

                            VStack(alignment: .leading, spacing: 2) {
                                Text(trs("Підтримуються лише документи України"))
                                    .font(.inter(13, .bold))
                                    .foregroundStyle(palette.coral)

                                Text(trs("Верифікація доступна для закордонного паспорта або ID-картки громадянина України."))
                                    .font(.lufga(12, .light))
                                    .foregroundStyle(palette.textSecondary)
                            }

                            Spacer()
                        }
                        .padding(14)
                        .background(palette.coral.opacity(0.12), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: 16, style: .continuous)
                                .stroke(palette.coral, lineWidth: 1)
                        )
                    }

                    // «Погане світло» — открывает ручной ввод
                    Button {
                        withAnimation(.easeInOut(duration: 0.2)) {
                            showManualMRZEntry.toggle()
                        }
                    } label: {
                        FigmaHint(
                            title: trs("Погане світло або відблиск?"),
                            subtitle: showManualMRZEntry ? trs("Сховати ручний ввід") : trs("Можна ввести MRZ вручну.")
                        )
                    }
                    .buttonStyle(.plain)

                    if showManualMRZEntry {
                        manualMRZFields
                    }

                    Button {
                        mrzScanner.stop()
                        screen = .nfc
                    } label: {
                        VerifyPrimaryButtonLabel(
                            title: trs("Продовжити"),
                            enabled: viewModel.mrzIsValid && viewModel.mrz.isUkrainian
                        )
                    }
                    .buttonStyle(.plain)
                    .disabled(viewModel.mrzIsValid == false || viewModel.mrz.isUkrainian == false)
                }
                .padding(.bottom, 20)
            }
        }
        .onAppear {
            mrzScanner.start()
        }
        .onDisappear {
            mrzScanner.stop()
        }
        .onChange(of: mrzScanner.scannedMRZ) { _, scanned in
            if let scanned {
                viewModel.mrz = scanned
            }
        }
    }

    /// Живая камера с полупрозрачным шаблоном паспорта для наведения.
    private var scannerViewport: some View {
        ZStack {
            if viewModel.mrzIsValid {
                // MRZ уже получен — камера остановлена
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .fill(palette.cardOlive)

                VStack(spacing: 10) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 44))
                        .foregroundStyle(palette.lime)

                    Text(trs("MRZ зчитано"))
                        .font(.inter(15, .bold))
                        .foregroundStyle(palette.textPrimary)
                }
            } else if mrzScanner.permissionDenied {
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .fill(palette.cardOlive)

                VStack(spacing: 8) {
                    Image(systemName: "video.slash.fill")
                        .font(.system(size: 34))
                        .foregroundStyle(palette.coral)

                    Text(trs("Немає доступу до камери"))
                        .font(.inter(14, .semibold))
                        .foregroundStyle(palette.textPrimary)

                    Text(trs("Дозволь камеру в Налаштуваннях або введи MRZ вручну."))
                        .font(.lufga(12, .light))
                        .foregroundStyle(palette.textSecondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 20)
                }
            } else {
                MRZCameraPreview(session: mrzScanner.session)
                    .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))

                // Полупрозрачная маска с окном-шаблоном документа
                passportOverlay
            }
        }
        .frame(height: 300)
        .frame(maxWidth: .infinity)
        .overlay(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .stroke(viewModel.mrzIsValid ? palette.lime : palette.lime.opacity(0.7), lineWidth: 1.5)
        )
    }

    /// Затемнение вокруг окна документа + подсвеченная MRZ-зона внизу.
    private var passportOverlay: some View {
        GeometryReader { geo in
            let inset: CGFloat = 22
            let docRect = CGRect(
                x: inset,
                y: geo.size.height * 0.18,
                width: geo.size.width - inset * 2,
                height: geo.size.height * 0.64
            )

            ZStack {
                // Затемнение с вырезом под документ
                Path { path in
                    path.addRect(CGRect(origin: .zero, size: geo.size))
                    path.addRoundedRect(
                        in: docRect,
                        cornerSize: CGSize(width: 14, height: 14)
                    )
                }
                .fill(Color.black.opacity(0.45), style: FillStyle(eoFill: true))

                // Рамка документа
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(palette.lime, style: StrokeStyle(lineWidth: 1.5, dash: [7, 5]))
                    .frame(width: docRect.width, height: docRect.height)
                    .position(x: docRect.midX, y: docRect.midY)

                // MRZ-зона (нижняя полоса документа)
                RoundedRectangle(cornerRadius: 5, style: .continuous)
                    .fill(palette.lime.opacity(0.28))
                    .overlay(
                        RoundedRectangle(cornerRadius: 5, style: .continuous)
                            .stroke(palette.lime, lineWidth: 1)
                    )
                    .frame(width: docRect.width - 20, height: 30)
                    .position(x: docRect.midX, y: docRect.maxY - 25)

                // Подсказка
                Text(trs("Наведи камеру на сторінку з фото"))
                    .font(.inter(12, .semibold))
                    .foregroundStyle(Color.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.black.opacity(0.55), in: Capsule())
                    .position(x: geo.size.width / 2, y: docRect.minY - 22)
            }
        }
        .allowsHitTesting(false)
    }

    /// Считанные MRZ-данные (после сканера или ручного ввода).
    private var scannedDataCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(trs("Номер документа"))
                    .foregroundStyle(palette.textSecondary)
                Spacer()
                Text(viewModel.mrz.normalizedDocumentNumber)
                    .foregroundStyle(palette.textPrimary)
                    .fontWeight(.semibold)
            }
            HStack {
                Text(trs("Дата народження"))
                    .foregroundStyle(palette.textSecondary)
                Spacer()
                Text(viewModel.mrz.dateOfBirth)
                    .foregroundStyle(palette.textPrimary)
                    .fontWeight(.semibold)
            }
            HStack {
                Text(trs("Дійсний до"))
                    .foregroundStyle(palette.textSecondary)
                Spacer()
                Text(viewModel.mrz.dateOfExpiry)
                    .foregroundStyle(palette.textPrimary)
                    .fontWeight(.semibold)
            }
        }
        .font(.system(size: 13, weight: .regular, design: .monospaced))
        .verifySurfaceCard(limeBorder: true)
    }

    /// Ручной ввод — показывается только по нажатию «Погане світло».
    private var manualMRZFields: some View {
        VStack(alignment: .leading, spacing: 14) {
            // Полная строка MRZ с проверкой чек-цифр ICAO 9303
            VStack(alignment: .leading, spacing: 7) {
                Text(trs("Рядок MRZ (44 символи)"))
                    .font(.inter(12, .semibold))
                    .foregroundStyle(palette.textSecondary)

                TextField(trs("Наприклад: AB1234567<8UKR…"), text: $viewModel.mrzLine)
                    .font(.system(size: 13, weight: .regular, design: .monospaced))
                    .foregroundStyle(palette.textPrimary)
                    .tint(palette.lime)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.characters)
                    .padding(14)
                    .liquidCard(cornerRadius: 14, fallback: palette.surface)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .stroke(
                                viewModel.mrzLineParseFailed ? palette.coral : palette.lime.opacity(0.5),
                                lineWidth: 1
                            )
                    )
                    .onChange(of: viewModel.mrzLine) { _, newValue in
                        viewModel.applyMRZLine(newValue)
                    }

                if viewModel.mrzLineParseFailed {
                    Text(trs("Не вдалося розібрати рядок — перевір символи або заповни поля нижче."))
                        .font(.lufga(11, .light))
                        .foregroundStyle(palette.coral)
                }
            }

            MrzField(
                title: trs("Номер документа"),
                placeholder: "AB123456",
                text: Binding(
                    get: { viewModel.mrz.documentNumber },
                    set: { viewModel.updateDocumentNumber($0) }
                ),
                isValid: viewModel.mrz.normalizedDocumentNumber.isEmpty == false,
                keyboard: .asciiCapable
            )

            MrzField(
                title: trs("Дата народження (YYMMDD)"),
                placeholder: "900315",
                text: Binding(
                    get: { viewModel.mrz.dateOfBirth },
                    set: { viewModel.updateDateOfBirth($0) }
                ),
                isValid: viewModel.mrz.dateOfBirth.count == 6,
                keyboard: .numberPad
            )

            MrzField(
                title: trs("Дата закінчення (YYMMDD)"),
                placeholder: "300101",
                text: Binding(
                    get: { viewModel.mrz.dateOfExpiry },
                    set: { viewModel.updateDateOfExpiry($0) }
                ),
                isValid: viewModel.mrz.dateOfExpiry.count == 6,
                keyboard: .numberPad
            )
        }
    }

    // MARK: - Крок 3 з 4: NFC

    private var nfcScreen: some View {
        stepScaffold(step: 3, onBack: { screen = .mrz }) {
            VStack(alignment: .leading, spacing: 14) {
                Text("Приклади документ\nдо iPhone")
                    .font(.inter(26, .heavy))
                    .foregroundStyle(palette.textPrimary)

                Text(trs("Тримай паспорт біля верхньої частини телефона, не рухай його до завершення зчитування."))
                    .font(.lufga(14, .light))
                    .foregroundStyle(palette.textSecondary)
                    .lineSpacing(3)

                HStack(spacing: 16) {
                    Spacer()

                    // Паспорт
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(palette.textSecondary.opacity(0.4))
                        .frame(width: 90, height: 110)
                        .overlay(
                            VStack(spacing: 6) {
                                Image(systemName: "person.crop.rectangle.fill")
                                    .font(.system(size: 30))
                                    .foregroundStyle(Color.white.opacity(0.85))

                                Image(systemName: "text.justify")
                                    .font(.system(size: 14))
                                    .foregroundStyle(Color.white.opacity(0.6))
                            }
                        )

                    // Телефон с NFC-волнами
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(palette.coral)
                        .frame(width: 70, height: 110)
                        .overlay(
                            Image(systemName: "wave.3.right")
                                .font(.system(size: 26, weight: .semibold))
                                .foregroundStyle(Color.white)
                        )

                    Spacer()
                }
                .frame(height: 180)
                .frame(maxWidth: .infinity)
                .verifyOliveCard()

                Spacer()

                VStack(spacing: 10) {
                    Text(nfcManager.result.title)
                        .font(.inter(15, .bold))
                        .foregroundStyle(palette.onLime)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 10)
                        .background(palette.lime, in: Capsule())

                    Text(nfcManager.result.message)
                        .font(.lufga(12, .light))
                        .foregroundStyle(palette.textSecondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)

                Button {
                    nfcManager.startScan(mrz: viewModel.mrz) { data in
                        if let data {
                            viewModel.passportData = data
                            screen = .face
                        } else {
                            screen = .nfcError
                        }
                    }
                } label: {
                    VerifyPrimaryButtonLabel(title: trs("Сканувати NFC"))
                }
                .buttonStyle(.plain)
            }
        }
    }

    // MARK: - Помилка NFC

    private var nfcErrorScreen: some View {
        VStack(spacing: 14) {
            VerifyTopBar()

            Spacer()

            Circle()
                .fill(palette.coral)
                .frame(width: 110, height: 110)
                .overlay(
                    Text("!")
                        .font(.inter(52, .heavy))
                        .foregroundStyle(Color.white)
                )

            Text(trs("NFC не зчитався"))
                .font(.inter(26, .heavy))
                .foregroundStyle(palette.textPrimary)

            Text(trs("Це нормально. Найчастіше допомагає змінити положення документа і не рухати телефон."))
                .font(.lufga(14, .light))
                .foregroundStyle(palette.textSecondary)
                .multilineTextAlignment(.center)

            // Фактическая причина ошибки с чипа
            if case .failed(let message) = nfcManager.result {
                Text(message)
                    .font(.lufga(12, .light))
                    .foregroundStyle(palette.coral)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 10)
            }

            VStack(spacing: 10) {
                ConsentRow(
                    title: trs("Перевір верхню частину iPhone"),
                    subtitle: trs("Саме там знаходиться NFC-зона"),
                    checked: true
                )
                ConsentRow(
                    title: trs("Зніми обкладинку з паспорта"),
                    subtitle: trs("Металізовані чохли можуть заважати"),
                    checked: true
                )
                ConsentRow(
                    title: trs("Тримай 10–20 секунд"),
                    subtitle: trs("Не рухай документ під час зчитування"),
                    checked: true
                )
            }

            Spacer()

            Button {
                nfcManager.reset()
                screen = .nfc
            } label: {
                VerifyCoralButtonLabel(title: trs("Спробувати ще раз"))
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 20)
        .padding(.top, 54)
        .padding(.bottom, 26)
    }

    // MARK: - Крок 4 з 4: face check

    private var faceScreen: some View {
        stepScaffold(step: 4, onBack: { screen = .nfc }) {
            VStack(alignment: .leading, spacing: 14) {
                Text("Підтверди,\nщо це ти")
                    .font(.inter(26, .heavy))
                    .foregroundStyle(palette.textPrimary)

                Text(trs("Зроби коротку перевірку обличчя. Ми звіримо тебе з фото з чипа документа."))
                    .font(.lufga(14, .light))
                    .foregroundStyle(palette.textSecondary)
                    .lineSpacing(3)

                ZStack {
                    Circle()
                        .fill(palette.surface)
                        .frame(width: 180, height: 180)

                    if faceManager.result.isCameraActive {
                        // Живое превью фронтальной камеры во время проверки
                        MRZCameraPreview(session: faceManager.session)
                            .frame(width: 180, height: 180)
                            .clipShape(Circle())
                            .scaleEffect(x: -1, y: 1) // зеркало, как привычно для селфи
                    } else if let liveFace = faceManager.capturedFace {
                        // Снятый кадр после прохождения liveness
                        Image(uiImage: liveFace)
                            .resizable()
                            .scaledToFill()
                            .frame(width: 180, height: 180)
                            .clipShape(Circle())
                    } else if let chipPhoto = nfcManager.chipPhoto {
                        // До старта — фото владельца с чипа (DG2)
                        Image(uiImage: chipPhoto)
                            .resizable()
                            .scaledToFill()
                            .frame(width: 180, height: 180)
                            .clipShape(Circle())
                    } else {
                        Image(systemName: "person.fill")
                            .font(.system(size: 70))
                            .foregroundStyle(palette.textSecondary)
                    }

                    Circle()
                        .stroke(palette.lime.opacity(0.4), lineWidth: 1)
                        .frame(width: 180, height: 180)

                    // Кольцо прогресса как при регистрации Face ID
                    FaceProgressRing(
                        progress: faceManager.faceConfidence,
                        isActive: faceManager.result.isCameraActive
                    )

                    // Миниатюра фото с чипа в углу, пока идёт съёмка
                    if faceManager.result.isCameraActive, let chipPhoto = nfcManager.chipPhoto {
                        Image(uiImage: chipPhoto)
                            .resizable()
                            .scaledToFill()
                            .frame(width: 56, height: 56)
                            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                            .shadow(color: palette.lime.opacity(0.16), radius: 5, y: 2)
                            .offset(x: 62, y: 62)
                    }
                }
                .frame(height: 250)
                .frame(maxWidth: .infinity)
                .verifyOliveCard()

                // Живая подсказка (свет / позиция / дистанция), как у Face ID
                if faceManager.result.isCameraActive, let guidance = faceManager.guidance {
                    Text(guidance)
                        .font(.inter(14, .semibold))
                        .foregroundStyle(Color.orange)
                        .frame(maxWidth: .infinity)
                        .multilineTextAlignment(.center)
                        .transition(.opacity)
                }

                HStack {
                    Text(faceManager.result.title)
                        .font(.inter(13, .semibold))
                        .foregroundStyle(palette.textPrimary)

                    Spacer()

                    Text("\(Int(faceManager.faceConfidence * 100))%")
                        .font(.inter(13, .bold))
                        .foregroundStyle(palette.lime)
                }
                .verifySurfaceCard(limeBorder: true)

                FigmaHint(
                    title: trs("Порада"),
                    subtitle: trs("Дивись у камеру, прибери темні окуляри, стань ближче до світла.")
                )

                if let faceMatchError {
                    Text(faceMatchError)
                        .font(.lufga(12, .light))
                        .foregroundStyle(palette.coral)
                        .multilineTextAlignment(.leading)
                }

                Spacer()

                Button {
                    startFaceCheck()
                } label: {
                    VerifyPrimaryButtonLabel(
                        title: isMatchingFace ? trs("Звіряємо з документом…") : trs("Почати face check"),
                        enabled: isMatchingFace == false
                    )
                }
                .buttonStyle(.plain)
                .disabled(isMatchingFace)
            }
        }
    }

    /// PRIVACY: стирает из памяти всё, что читалось с документа.
    /// В приложении остаётся только статус Verified ID.
    private func wipeSensitiveData() {
        viewModel.reset()                 // passportData = nil
        viewModel.mrz = PassportMRZ()     // MRZ-ключ
        viewModel.mrzLine = ""
        nfcManager.reset()                // chipPhoto (DG2) + результат
        faceManager.reset()               // кадр лица с камеры
    }

    /// Liveness → сверка живого лица с фото из DG2 чипа.
    private func startFaceCheck() {
        faceMatchError = nil

        faceManager.startCheck { success in
            guard success else { return }

            guard
                let chipPhoto = nfcManager.chipPhoto,
                let liveFace = faceManager.capturedFace
            else {
                // FAIL-CLOSED: немає фото з чипа (DG2) або кадру обличчя —
                // сверку зробити НЕМОЖЛИВО, тож верифікація НЕ проходить.
                // Раніше тут був fail-open (одразу «успіх») — критична дірка:
                // документ без читабельного DG2 підтверджувався без обличчя.
                faceMatchError = trs("Не вдалося прочитати фото з чипа документа. Верифікація неможлива без звірки обличчя.")
                faceManager.reset()
                return
            }

            // Блокуємо повторний запуск, поки триває звірка/підтвердження
            guard isMatchingFace == false else { return }
            isMatchingFace = true

            Task {
                do {
                    let result = try await FaceMatcher.match(chipPhoto: chipPhoto, liveFace: liveFace)

                    switch result.verdict {
                    case .match:
                        // Обличчя збіглось → ЧЕСНІ докази на сервер.
                        // Успіх показуємо ЛИШЕ після підтвердження бази,
                        // а не до нього (раніше UI брехав про Verified).
                        //
                        // SOD + хеші DG — сервер САМ виконує Passive
                        // Authentication (підпис держави → CSCA України).
                        // Персональні поля документа не передаються.
                        let evidence = VerificationEvidence(
                            liveness: faceManager.livenessMode == "depth" ? .depth : .heuristic,
                            faceMatch: .passed,
                            faceModel: result.model,
                            sodBase64: nfcManager.chipSOD?.base64EncodedString(),
                            dgHashes: nfcManager.dgHashes
                        )
                        let saved = await CurrentSession.shared.markVerified(evidence: evidence)

                        await MainActor.run {
                            isMatchingFace = false
                            if saved {
                                wipeSensitiveData()
                                screen = .success
                            } else {
                                faceMatchError = session.verifySyncError
                                    ?? trs("Сервер не підтвердив статус.")
                                faceManager.reset()
                            }
                        }

                    case .uncertain(let similarity):
                        await MainActor.run {
                            isMatchingFace = false
                            faceMatchError = "Не вдалося впевнено зіставити обличчя (схожість \(Int(similarity * 100))%). Спробуй ще раз при кращому освітленні, без окулярів."
                            faceManager.reset()
                        }

                    case .noMatch:
                        await MainActor.run {
                            isMatchingFace = false
                            faceMatchError = "Обличчя не збігається з фото з чипа документа. Верифікацію може пройти лише власник документа."
                            faceManager.reset()
                        }
                    }
                } catch {
                    await MainActor.run {
                        isMatchingFace = false
                        faceMatchError = AppErrors.text(error) + " (E-401)"
                        faceManager.reset()
                    }
                }
            }
        }
    }

    // MARK: - Успіх

    private var successScreen: some View {
        VStack(spacing: 14) {
            VerifyTopBar()

            Spacer()

            Circle()
                .fill(palette.lime)
                .frame(width: 120, height: 120)
                .overlay(
                    Image(systemName: "checkmark")
                        .font(.system(size: 50, weight: .bold))
                        .foregroundStyle(palette.onLime)
                )

            Text("Верифікацію\nпройдено")
                .font(.inter(28, .heavy))
                .foregroundStyle(palette.textPrimary)
                .multilineTextAlignment(.center)

            (
                Text(trs("Твій профіль отримав статус Verified"))
                    .foregroundStyle(palette.textSecondary)
                + Text("ID")
                    .foregroundStyle(palette.coral)
                    .fontWeight(.bold)
                + Text(".\nТепер можна користуватися довіреними сервісами OstrovUA.")
                    .foregroundStyle(palette.textSecondary)
            )
            .font(.lufga(14, .light))
            .multilineTextAlignment(.center)

            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 12) {
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(palette.cardOlive)
                        .frame(width: 48, height: 48)
                        .overlay(
                            Text("UA")
                                .font(.inter(15, .bold))
                                .foregroundStyle(palette.lime)
                        )

                    VStack(alignment: .leading, spacing: 2) {
                        // PRIVACY: данные документа стёрты — показываем только статус
                        Text(trs("Учасник OstrovUA"))
                            .font(.inter(16, .bold))
                            .foregroundStyle(palette.textPrimary)

                        (
                            Text("Verified ")
                                .foregroundStyle(palette.textPrimary)
                            + Text("ID")
                                .foregroundStyle(palette.coral)
                        )
                        .font(.inter(12, .bold))
                    }

                    Spacer()
                }

                HStack(spacing: 10) {
                    Text(trs("Профіль активний"))
                        .font(.inter(12, .semibold))
                        .foregroundStyle(palette.onLime)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 6)
                        .background(palette.lime, in: Capsule())

                    Text("UA")
                        .font(.inter(12, .semibold))
                        .foregroundStyle(Color.white)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 6)
                        .background(palette.coral, in: Capsule())
                }
            }
            .verifySurfaceCard(limeBorder: true)

            Spacer()

            // Статус Verified ID уже записаний у базу на кроці звірки
            // обличчя (fail-closed: без підтвердження сервера екран успіху
            // взагалі не показується). Тут — лише перехід до профілю.
            Button {
                screen = .profileSetup
            } label: {
                VerifyCoralButtonLabel(title: trs("Продовжити"))
            }
            .buttonStyle(.plain)

            if let error = session.verifySyncError {
                Text(error)
                    .font(.lufga(12, .light))
                    .foregroundStyle(palette.coral)
                    .multilineTextAlignment(.center)
            }

            Text(trs("Дані документа не зберігаються — лише статус Verified ID"))
                .font(.lufga(11, .light))
                .foregroundStyle(palette.textSecondary)
        }
        .padding(.horizontal, 20)
        .padding(.top, 54)
        .padding(.bottom, 26)
    }
}

// MARK: - Створи профіль (ник + фото, добровольно)

extension VerificationView {
    private var profileSetupScreen: some View {
        VStack(spacing: 16) {
            VerifyTopBar()

            Spacer()

            Text(trs("Створи свій профіль"))
                .font(.inter(26, .heavy))
                .foregroundStyle(palette.textPrimary)
                .multilineTextAlignment(.center)

            Text(trs("Як тебе бачитиме спільнота. Дані документа не зберігаються — нік і фото ти обираєш сам."))
                .font(.lufga(14, .light))
                .foregroundStyle(palette.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 12)

            // Фото профиля (по желанию)
            PhotosPicker(selection: $selectedPhoto, matching: .images) {
                ZStack {
                    Circle()
                        .fill(palette.surface)
                        .frame(width: 140, height: 140)

                    if let avatarImage {
                        Image(uiImage: avatarImage)
                            .resizable()
                            .scaledToFill()
                            .frame(width: 140, height: 140)
                            .clipShape(Circle())
                    } else {
                        VStack(spacing: 6) {
                            Image(systemName: "camera.fill")
                                .font(.system(size: 28))
                                .foregroundStyle(palette.textSecondary)

                            Text(trs("Додати фото"))
                                .font(.lufga(12, .light))
                                .foregroundStyle(palette.textSecondary)
                        }
                    }

                    Circle()
                        .stroke(palette.lime, lineWidth: 1.5)
                        .frame(width: 140, height: 140)

                    Circle()
                        .fill(palette.lime)
                        .frame(width: 34, height: 34)
                        .overlay(
                            Image(systemName: avatarImage == nil ? "plus" : "pencil")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundStyle(palette.onLime)
                        )
                        .offset(x: 48, y: 48)
                }
            }
            .buttonStyle(.plain)
            .onChange(of: selectedPhoto) { _, item in
                Task {
                    if let data = try? await item?.loadTransferable(type: Data.self),
                       let image = UIImage(data: data) {
                        avatarImage = image
                    }
                }
            }

            // Ник (по желанию)
            VStack(alignment: .leading, spacing: 7) {
                Text(trs("Нік"))
                    .font(.inter(12, .semibold))
                    .foregroundStyle(palette.textSecondary)

                TextField(trs("Наприклад: Danylo_UA"), text: $nickname)
                    .font(.lufga(15, .light))
                    .foregroundStyle(palette.textPrimary)
                    .tint(palette.lime)
                    .autocorrectionDisabled()
                    .padding(14)
                    .liquidCard(cornerRadius: 14, fallback: palette.surface)
                    .shadow(color: palette.lime.opacity(0.08), radius: 4, y: 1)
            }
            .padding(.horizontal, 4)

            Spacer()

            Button {
                CurrentSession.shared.saveProfile(nickname: nickname, avatar: avatarImage)
                router.startApp()
            } label: {
                VerifyPrimaryButtonLabel(
                    title: trs("Зберегти і почати"),
                    enabled: nickname.trimmingCharacters(in: .whitespaces).isEmpty == false || avatarImage != nil
                )
            }
            .buttonStyle(.plain)
            .disabled(nickname.trimmingCharacters(in: .whitespaces).isEmpty && avatarImage == nil)

            Button {
                router.startApp()
            } label: {
                Text(trs("Пропустити"))
                    .font(.lufga(14, .light))
                    .foregroundStyle(palette.textSecondary)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 20)
        .padding(.top, 54)
        .padding(.bottom, 26)
    }
}

// MARK: - Компоненты

/// Кольцо прогресса в стиле регистрации Face ID:
/// радиальные чёрточки вокруг круга, заполняются lime по мере прогресса.
private struct FaceProgressRing: View {
    let progress: Double   // 0…1
    let isActive: Bool

    @Environment(\.colorScheme) private var colorScheme

    private let tickCount = 48
    private let radius: CGFloat = 106

    var body: some View {
        let palette = VerifyPalette.palette(for: colorScheme)
        let filled = Int((progress * Double(tickCount)).rounded())

        ZStack {
            ForEach(0..<tickCount, id: \.self) { index in
                Capsule()
                    .fill(index < filled ? palette.lime : palette.textSecondary.opacity(isActive ? 0.35 : 0.18))
                    .frame(width: 3.5, height: 14)
                    .offset(y: -radius)
                    .rotationEffect(.degrees(Double(index) / Double(tickCount) * 360))
            }
        }
        .animation(.easeOut(duration: 0.25), value: filled)
    }
}

private struct ConsentRow: View {
    let title: String
    let subtitle: String
    var icon: String = ""
    var checked: Bool = false

    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        let palette = VerifyPalette.palette(for: colorScheme)

        HStack(spacing: 12) {
            Circle()
                .fill(checked ? palette.lime : palette.coral)
                .frame(width: 30, height: 30)
                .overlay(
                    Group {
                        if checked {
                            Image(systemName: "checkmark")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundStyle(palette.onLime)
                        } else if icon.isEmpty == false {
                            Image(systemName: icon)
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(Color.white)
                        }
                    }
                )

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.inter(15, .semibold))
                    .foregroundStyle(palette.textPrimary)

                Text(subtitle)
                    .font(.lufga(12, .light))
                    .foregroundStyle(palette.textSecondary)
            }

            Spacer()
        }
        .verifySurfaceCard(limeBorder: true)
    }
}

private struct MrzField: View {
    let title: String
    let placeholder: String
    @Binding var text: String
    let isValid: Bool
    var keyboard: UIKeyboardType = .default

    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        let palette = VerifyPalette.palette(for: colorScheme)

        VStack(alignment: .leading, spacing: 7) {
            Text(title)
                .font(.inter(12, .semibold))
                .foregroundStyle(palette.textSecondary)

            HStack(spacing: 10) {
                TextField(placeholder, text: $text)
                    .font(.system(size: 15, weight: .regular, design: .monospaced))
                    .foregroundStyle(palette.textPrimary)
                    .tint(palette.lime)
                    .keyboardType(keyboard)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.characters)

                if text.isEmpty == false {
                    Image(systemName: isValid ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                        .foregroundStyle(isValid ? palette.lime : palette.coral)
                }
            }
            .padding(14)
            .liquidCard(cornerRadius: 14, fallback: palette.surface)
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(
                        text.isEmpty ? palette.lime.opacity(0.5) : (isValid ? palette.lime : palette.coral),
                        lineWidth: 1
                    )
            )
        }
    }
}

private struct FigmaHint: View {
    let title: String
    let subtitle: String

    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        let palette = VerifyPalette.palette(for: colorScheme)

        HStack(alignment: .top, spacing: 10) {
            Circle()
                .stroke(palette.lime, lineWidth: 1)
                .frame(width: 22, height: 22)
                .overlay(
                    Text("i")
                        .font(.inter(11, .bold))
                        .foregroundStyle(palette.lime)
                )

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.inter(13, .semibold))
                    .foregroundStyle(palette.textPrimary)

                Text(subtitle)
                    .font(.lufga(12, .light))
                    .foregroundStyle(palette.textSecondary)
            }

            Spacer()
        }
        .verifySurfaceCard()
    }
}

#Preview("Верифікація — ніч") {
    VerificationView(router: AppRouter())
        .preferredColorScheme(.dark)
}

#Preview("Верифікація — день") {
    VerificationView(router: AppRouter())
        .preferredColorScheme(.light)
}
