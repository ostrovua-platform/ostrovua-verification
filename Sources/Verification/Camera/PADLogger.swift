import Foundation

#if DEBUG
/// PAD-логер (ЛИШЕ DEBUG, аудит #8): збирає виміряний depth-RMS кожного
/// кадру з поточною міткою презентації для оцінки APCER/BPCER.
///
/// Процедура вимірювання:
///  1. Оператор ставить мітку поточної презентації через `label`
///     (жива особа = "bonafide", атаки = "print"/"screen"/"mask"…).
///  2. Проходить крок face-check, пред'являючи відповідний артефакт.
///  3. Кожен кадр із порахованим RMS дописується у Documents/pad_log.csv.
///  4. CSV вивантажується (Files/AirDrop) і аналізується Tools/PADScore.
///
///  У RELEASE-збірці цього класу НЕМАЄ — нічого не пишеться.
final class PADLogger {
    static let shared = PADLogger()

    /// Мітка поточної презентації (виставляє оператор у debug-оверлеї).
    var label: String = "bonafide"

    private let queue = DispatchQueue(label: "ostrovua.pad.logger")
    private lazy var url: URL = {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return dir.appendingPathComponent("pad_log.csv")
    }()

    private init() {}

    func record(rms: Double?) {
        let ts = Date().timeIntervalSince1970
        let lbl = label
        let value = rms.map { String(format: "%.6f", $0) } ?? "nil"
        queue.async {
            if FileManager.default.fileExists(atPath: self.url.path) == false {
                try? "timestamp,label,rms_m\n".write(to: self.url, atomically: true, encoding: .utf8)
            }
            if let h = try? FileHandle(forWritingTo: self.url) {
                h.seekToEndOfFile()
                h.write("\(ts),\(lbl),\(value)\n".data(using: .utf8)!)
                try? h.close()
            }
        }
    }

    /// Шлях до CSV — для кнопки «поділитися» в debug-оверлеї.
    var fileURL: URL { url }

    func reset() {
        queue.async { try? FileManager.default.removeItem(at: self.url) }
    }
}
#endif
