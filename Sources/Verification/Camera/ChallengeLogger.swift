import Foundation
import Combine

/// Телеметрія активної liveness для вимірювання (аудит #8).
/// НЕ під DEBUG: стенд видимий у беті (рішення Dani) — тестери збирають
/// дані. Пише лише локальний CSV; жодних серверних викликів.
/// Пише покадрово: мітка презентації, стан челенджу, yaw/pitch/ear і
/// результат попитки (completed). Файл pad_challenge.csv → Tools/PADScore.
final class ChallengeLogger: ObservableObject {
    static let shared = ChallengeLogger()

    var label: String = "bonafide"
    @Published private(set) var frames: Int = 0
    @Published private(set) var attempts: Int = 0
    @Published private(set) var completed: Int = 0

    /// Лічильники ПО КЛАСУ (bonafide/photo/screen/…) — щоб оператор бачив,
    /// скільки попиток кожного класу вже зібрано, і знав, коли досить для
    /// довірчого інтервалу (див. Tools/PADScore/challenge_score.py).
    struct LabelCount: Equatable { var attempts = 0; var passed = 0 }
    @Published private(set) var counts: [String: LabelCount] = [:]

    private let queue = DispatchQueue(label: "ostrovua.challenge.logger")
    private lazy var url: URL = {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return dir.appendingPathComponent("pad_challenge.csv")
    }()

    private init() {}
    var fileURL: URL { url }

    /// glare/hf — ознаки артефактів екрана (муар/відблиск, ScreenArtifactDetector);
    /// depth — рельєф глибини точок обличчя (нос vs щоки), додається пізніше.
    /// Усі вимірювані сигнали анти-реплею логуємо поруч для скорингу.
    func frame(state: String, yaw: Double?, pitch: Double?, ear: Double?,
               glare: Double? = nil, hf: Double? = nil, depth: Double? = nil) {
        let lbl = label
        let row = "\(Date().timeIntervalSince1970),\(lbl),\(state)," +
                  "\(fmt(yaw)),\(fmt(pitch)),\(fmt(ear))," +
                  "\(fmt(glare)),\(fmt(hf)),\(fmt(depth))\n"
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
            self.append("\(Date().timeIntervalSince1970),\(lbl),ATTEMPT_\(passed ? "PASS" : "FAIL"),,,,,,\n")
            DispatchQueue.main.async {
                self.attempts += 1
                if passed { self.completed += 1 }
                var c = self.counts[lbl] ?? LabelCount()
                c.attempts += 1; if passed { c.passed += 1 }
                self.counts[lbl] = c
            }
        }
    }

    func reset() {
        queue.async {
            try? FileManager.default.removeItem(at: self.url)
            DispatchQueue.main.async { self.frames = 0; self.attempts = 0; self.completed = 0; self.counts = [:] }
        }
    }

    private func fmt(_ v: Double?) -> String { v.map { String(format: "%.4f", $0) } ?? "" }
    private func ensureHeader() {
        if FileManager.default.fileExists(atPath: url.path) == false {
            try? "timestamp,label,state,yaw,pitch,ear,glare,hf,depth\n".write(to: url, atomically: true, encoding: .utf8)
        }
    }
    private func append(_ s: String) {
        if let h = try? FileHandle(forWritingTo: url) {
            h.seekToEndOfFile(); h.write(s.data(using: .utf8)!); try? h.close()
        }
    }
}
