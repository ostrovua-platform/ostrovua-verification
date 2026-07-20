import Foundation
import Combine

#if DEBUG
/// Телеметрія активної liveness для вимірювання (аудит #8).
/// Пише покадрово: мітка презентації, стан челенджу, yaw/pitch/ear і
/// результат попитки (completed). Файл pad_challenge.csv → Tools/PADScore.
final class ChallengeLogger: ObservableObject {
    static let shared = ChallengeLogger()

    var label: String = "bonafide"
    @Published private(set) var frames: Int = 0
    @Published private(set) var attempts: Int = 0
    @Published private(set) var completed: Int = 0

    private let queue = DispatchQueue(label: "ostrovua.challenge.logger")
    private lazy var url: URL = {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return dir.appendingPathComponent("pad_challenge.csv")
    }()

    private init() {}
    var fileURL: URL { url }

    func frame(state: String, yaw: Double?, pitch: Double?, ear: Double?) {
        let lbl = label
        let row = "\(Date().timeIntervalSince1970),\(lbl),\(state)," +
                  "\(fmt(yaw)),\(fmt(pitch)),\(fmt(ear))\n"
        queue.async {
            self.ensureHeader()
            self.append(row)
            DispatchQueue.main.async { self.frames += 1 }
        }
    }

    /// Викликати наприкінці кожної попитки.
    func attemptFinished(passed: Bool) {
        let lbl = label
        queue.async {
            self.ensureHeader()
            self.append("\(Date().timeIntervalSince1970),\(lbl),ATTEMPT_\(passed ? "PASS" : "FAIL"),,,\n")
            DispatchQueue.main.async {
                self.attempts += 1
                if passed { self.completed += 1 }
            }
        }
    }

    func reset() {
        queue.async {
            try? FileManager.default.removeItem(at: self.url)
            DispatchQueue.main.async { self.frames = 0; self.attempts = 0; self.completed = 0 }
        }
    }

    private func fmt(_ v: Double?) -> String { v.map { String(format: "%.4f", $0) } ?? "" }
    private func ensureHeader() {
        if FileManager.default.fileExists(atPath: url.path) == false {
            try? "timestamp,label,state,yaw,pitch,ear\n".write(to: url, atomically: true, encoding: .utf8)
        }
    }
    private func append(_ s: String) {
        if let h = try? FileHandle(forWritingTo: url) {
            h.seekToEndOfFile(); h.write(s.data(using: .utf8)!); try? h.close()
        }
    }
}
#endif
