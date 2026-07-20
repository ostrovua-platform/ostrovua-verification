import Foundation
import Combine

#if DEBUG
/// PAD-логер (ЛИШЕ DEBUG, аудит #8): збирає виміряний depth-RMS кожного
/// кадру з поточною міткою презентації для оцінки APCER/BPCER.
///
/// ВЕРСІЯ 2 (синхронайзер + ROI): файл називається pad_log_v2.csv, щоб
/// його НЕМОЖЛИВО було сплутати зі старим pad_log.csv. Лічильник count
/// показується в оверлеї наживо — видно, що новий білд реально пише.
///
/// У RELEASE-збірці цього класу НЕМАЄ.
final class PADLogger: ObservableObject {
    static let shared = PADLogger()

    /// Мітка поточної презентації (виставляє оператор у debug-оверлеї).
    var label: String = "bonafide"

    /// Скільки кадрів записано (наживо в оверлеї — доказ, що білд новий).
    @Published private(set) var count: Int = 0

    private let queue = DispatchQueue(label: "ostrovua.pad.logger")
    private lazy var url: URL = {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        // v3 = центральне вікно (ROI-трансформу відкочено) + синхронайзер.
        return dir.appendingPathComponent("pad_log_v3.csv")
    }()

    private init() {}

    func record(rms: Double?) {
        let ts = Date().timeIntervalSince1970
        let lbl = label
        let value = rms.map { String(format: "%.6f", $0) } ?? "nil"
        queue.async {
            if FileManager.default.fileExists(atPath: self.url.path) == false {
                // build-колонка = маркер версії білда (v2 = синхронайзер+ROI)
                try? "timestamp,label,rms_m,build\n"
                    .write(to: self.url, atomically: true, encoding: .utf8)
            }
            if let h = try? FileHandle(forWritingTo: self.url) {
                h.seekToEndOfFile()
                h.write("\(ts),\(lbl),\(value),v3\n".data(using: .utf8)!)
                try? h.close()
            }
            DispatchQueue.main.async { self.count += 1 }
        }
    }

    /// Шлях до CSV — для кнопки «поділитися» в debug-оверлеї.
    var fileURL: URL { url }

    func reset() {
        queue.async {
            try? FileManager.default.removeItem(at: self.url)
            DispatchQueue.main.async { self.count = 0 }
        }
    }
}
#endif
