import SwiftUI
import ARKit

/// Екран заміру РЕЛЬЄФУ ГЛИБИНИ (TrueDepth/ARKit) — окремо від позового
/// стенда (ARKit і AVCapture не ділять камеру). Оператор ставить мітку
/// (bonafide/photo/screen), тримає обличчя/атаку в кадрі; std сирої
/// глибини пишеться в колонку `depth`. Export → challenge_score.py
/// покаже, чи рельєф РОЗДІЛЯЄ живе обличчя й плоский екран.
/// Самодостатній: сервер не кличе, Verified ID не видає.
struct DepthReliefMeasureView: View {
    @StateObject private var manager = DepthReliefManager()
    @ObservedObject private var logger = ChallengeLogger.shared
    @State private var label = "bonafide"
    @State private var showShare = false
    private let labels = ["bonafide", "photo", "screen", "other"]

    var body: some View {
        VStack(spacing: 10) {
            Text("Рельєф глибини — вимір").font(.headline)
            Text("TrueDepth: живе обличчя має рельєф, екран/фото — плоскі. На верифікацію НЕ впливає.")
                .font(.caption2).foregroundColor(.secondary)
                .multilineTextAlignment(.center).padding(.horizontal)

            if manager.supported {
                ARDepthPreview(session: manager.session)
                    .frame(height: 300).clipShape(RoundedRectangle(cornerRadius: 16))
            } else {
                RoundedRectangle(cornerRadius: 16).fill(Color.gray.opacity(0.2))
                    .frame(height: 300)
                    .overlay(Text("TrueDepth недоступний\n(потрібен iPhone з Face ID)")
                        .multilineTextAlignment(.center).foregroundColor(.secondary).padding())
            }

            Text(manager.reliefText).font(.callout).bold()

            Picker("label", selection: $label) {
                ForEach(labels, id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented)
            .onChange(of: label) { _, v in ChallengeLogger.shared.label = v }

            Text("кадрів depth: \(logger.frames)  ·  збери bonafide vs screen/photo")
                .font(.caption).foregroundColor(.secondary)

            HStack(spacing: 20) {
                Button("Export") { showShare = true }
                Button("Reset") { ChallengeLogger.shared.reset() }.foregroundColor(.red)
            }
        }
        .padding()
        .onAppear { ChallengeLogger.shared.label = label; manager.start() }
        .onDisappear { manager.stop() }
        .sheet(isPresented: $showShare) { ShareSheetD(items: [ChallengeLogger.shared.fileURL]) }
    }
}

private struct ARDepthPreview: UIViewRepresentable {
    let session: ARSession
    func makeUIView(context: Context) -> ARSCNView {
        let v = ARSCNView()
        v.session = session          // менеджер сам запускає конфіг
        v.automaticallyUpdatesLighting = true
        return v
    }
    func updateUIView(_ v: ARSCNView, context: Context) {}
}

private struct ShareSheetD: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
