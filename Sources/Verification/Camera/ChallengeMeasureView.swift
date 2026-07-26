import SwiftUI
import AVFoundation

#if DEBUG
/// Екран вимірювання активної liveness (челендж-response, аудит #8).
/// Видимий у беті (рішення Dani) для збору тестерами; самодостатній —
/// своя камера, лише логування у CSV, сервер не кличе, нічого не видає.
/// Оператор: ставить мітку, тисне «Нова попитка», виконує (живим обличчям
/// або атакою) послідовність дій; телеметрія пишеться, наприкінці — Export.
struct ChallengeMeasureView: View {
    @StateObject private var manager = ChallengeMeasureManager()
    @ObservedObject private var logger = ChallengeLogger.shared
    @State private var label = "bonafide"
    @State private var showShare = false
    #if DEBUG
    @State private var showDepth = false
    #endif
    private let labels = ["bonafide", "photo", "screen", "other"]
    // Цілі збору на клас: дають ~10% верхню межу APCER (Wilson 95%) —
    // досяжно за пару сесій. Для 5% межі треба ~73 (скаже
    // Tools/PADScore/challenge_score.py). bonafide 20 → BPCER з довірою.
    private let targets: [String: Int] = ["bonafide": 20, "photo": 35, "screen": 35, "other": 0]

    var body: some View {
        VStack(spacing: 10) {
            Text("Active liveness — вимір").font(.headline)

            // Плашка для тестерів: що це і що робити (рішення Dani).
            VStack(spacing: 4) {
                Text("Інструмент заміру. На верифікацію НЕ впливає, Verified ID НЕ видає.")
                    .foregroundColor(.secondary)
                Text("Знімай bonafide (живе), photo і screen. ВАЖЛИВО: додай і ЧУЖЕ обличчя — це незалежна перевірка.")
                    .foregroundColor(.orange)
            }
            .font(.caption2).multilineTextAlignment(.center)
            .padding(8)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10))

            CameraPreview(session: manager.session)
                .frame(height: 280).clipShape(RoundedRectangle(cornerRadius: 16))

            Text(manager.guidance).multilineTextAlignment(.center).font(.callout)
            Text(manager.passedText).bold()
                .foregroundColor(manager.passedText.hasPrefix("✓") ? .green : .red)

            Picker("label", selection: $label) {
                ForEach(labels, id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented)
            .onChange(of: label) { _, v in ChallengeLogger.shared.label = v }

            // Прогрес збору ПО КЛАСУ — щоб бачити, коли зібрано досить.
            VStack(spacing: 3) {
                ForEach(labels, id: \.self) { lbl in
                    let c = logger.counts[lbl] ?? ChallengeLogger.LabelCount()
                    let target = targets[lbl] ?? 0
                    HStack(spacing: 6) {
                        Text(lbl).frame(width: 74, alignment: .leading)
                        if lbl == "bonafide" {
                            Text("\(c.attempts)/\(target)  пройдено \(c.passed)")
                        } else {
                            Text("\(c.attempts)/\(target)" + (c.passed > 0 ? "  ✗\(c.passed) ПРОЙШЛИ!" : ""))
                                .foregroundColor(c.passed > 0 ? .red : .primary)
                        }
                        Spacer()
                        if target > 0 && c.attempts >= target {
                            Image(systemName: "checkmark.circle.fill").foregroundColor(.green)
                        }
                    }
                    .font(.caption)
                }
                Text("кадрів: \(logger.frames)  ·  ціль дає ~10% верхню межу APCER")
                    .font(.caption2).foregroundColor(.secondary)
            }

            HStack {
                Button("Нова попитка") { manager.newAttempt() }.buttonStyle(.borderedProminent)
                Button("Export") { showShare = true }
                Button("Reset") { ChallengeLogger.shared.reset() }.foregroundColor(.red)
            }

            #if DEBUG
            // Окремий зонд рельєфу глибини (TrueDepth/ARKit) — DEBUG-only
            // (DepthReliefMeasureView під #if DEBUG).
            Button { showDepth = true } label: {
                Text("🔬 Рельєф глибини (TrueDepth)").font(.caption).bold()
            }
            #endif
        }
        #if DEBUG
        .sheet(isPresented: $showDepth) { DepthReliefMeasureView() }
        #endif
        .padding()
        .onAppear { ChallengeLogger.shared.label = label; manager.startSession() }
        .onDisappear { manager.stopSession() }
        .sheet(isPresented: $showShare) { ShareSheetC(items: [ChallengeLogger.shared.fileURL]) }
    }
}
#endif

private struct CameraPreview: UIViewRepresentable {
    let session: AVCaptureSession
    func makeUIView(context: Context) -> PreviewUIView {
        let v = PreviewUIView()
        v.previewLayer.session = session
        v.previewLayer.videoGravity = .resizeAspectFill
        return v
    }
    func updateUIView(_ v: PreviewUIView, context: Context) {}
    final class PreviewUIView: UIView {
        override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
        var previewLayer: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
    }
}

private struct ShareSheetC: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
