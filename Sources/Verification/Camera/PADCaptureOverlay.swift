import SwiftUI

#if DEBUG
/// Debug-оверлей для PAD-вимірювання (аудит #8). Показується поверх
/// екрана face-check ЛИШЕ у DEBUG. Дозволяє оператору перемкнути мітку
/// поточної презентації і вивантажити зібраний CSV.
struct PADCaptureOverlay: View {
    @State private var label = "bonafide"
    @State private var showShare = false

    private let labels = ["bonafide", "print", "screen", "mask", "other"]

    var body: some View {
        VStack(spacing: 8) {
            Text("PAD capture (DEBUG)").font(.caption2).bold()
            Picker("label", selection: $label) {
                ForEach(labels, id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented)
            .onChange(of: label) { _, new in PADLogger.shared.label = new }

            HStack {
                Button("Export CSV") { showShare = true }
                    .font(.caption2)
                Button("Reset") { PADLogger.shared.reset() }
                    .font(.caption2).foregroundColor(.red)
            }
        }
        .padding(8)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10))
        .padding(8)
        .onAppear { PADLogger.shared.label = label }
        .sheet(isPresented: $showShare) {
            ShareSheet(items: [PADLogger.shared.fileURL])
        }
    }
}

private struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
#endif
