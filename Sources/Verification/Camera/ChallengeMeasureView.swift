import SwiftUI
import AVFoundation

#if DEBUG
/// DEBUG-екран вимірювання активної liveness (челендж-response, аудит #8).
/// Оператор: ставить мітку, тисне «Нова попитка», виконує (живим обличчям
/// або атакою) послідовність дій; телеметрія пишеться, наприкінці — Export.
struct ChallengeMeasureView: View {
    @StateObject private var manager = ChallengeMeasureManager()
    @ObservedObject private var logger = ChallengeLogger.shared
    @State private var label = "bonafide"
    @State private var showShare = false
    private let labels = ["bonafide", "photo", "screen", "other"]

    var body: some View {
        VStack(spacing: 12) {
            Text("Active liveness — вимір").font(.headline)

            CameraPreview(session: manager.session)
                .frame(height: 320).clipShape(RoundedRectangle(cornerRadius: 16))

            Text(manager.guidance).multilineTextAlignment(.center).font(.callout)
            Text(manager.passedText).bold()
                .foregroundColor(manager.passedText.hasPrefix("✓") ? .green : .red)

            Picker("label", selection: $label) {
                ForEach(labels, id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented)
            .onChange(of: label) { _, v in ChallengeLogger.shared.label = v }

            Text("попиток: \(logger.attempts)  пройдено: \(logger.completed)  кадрів: \(logger.frames)")
                .font(.caption).foregroundColor(.secondary)

            HStack {
                Button("Нова попитка") { manager.newAttempt() }.buttonStyle(.borderedProminent)
                Button("Export") { showShare = true }
                Button("Reset") { ChallengeLogger.shared.reset() }.foregroundColor(.red)
            }
        }
        .padding()
        .onAppear { ChallengeLogger.shared.label = label; manager.startSession() }
        .onDisappear { manager.stopSession() }
        .sheet(isPresented: $showShare) { ShareSheetC(items: [ChallengeLogger.shared.fileURL]) }
    }
}

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
#endif
