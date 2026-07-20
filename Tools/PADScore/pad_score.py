#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
#  PAD-скоринг (аудит #8). Рахує APCER / BPCER із pad_log.csv на ДВОХ
#  рівнях і СМУГОЮ, що ТОЧНО відповідає бойовому gate:
#     кадр «живий» ⇔ lower ≤ RMS ≤ upper   (за замовч. 5..20 мм)
#
#  Рівні:
#   • frame-level: частка окремих кадрів.
#   • attempt-level: рішення попитки = 12 ПОСЛІДОВНИХ кадрів у смузі
#     (як liveness). Попитки сегментуються за розривами часу
#     (>2 c між кадрами = нова попитка).
#
#  Використання:
#    python3 pad_score.py pad_log.csv [--lower 0.005] [--upper 0.020]
#                                     [--consecutive 12] [--gap 2.0]
# ═══════════════════════════════════════════════════════════════════
import csv, argparse
from collections import defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("csv")
ap.add_argument("--lower", type=float, default=0.005)
ap.add_argument("--upper", type=float, default=0.020)
ap.add_argument("--consecutive", type=int, default=12)
ap.add_argument("--gap", type=float, default=2.0, help="розрив часу (с) = нова попитка")
a = ap.parse_args()

rows = defaultdict(list)   # label -> [(ts, rms|None)]
for r in csv.DictReader(open(a.csv)):
    v = r["rms_m"].strip()
    rows[r["label"]].append((float(r["timestamp"]), None if v == "nil" else float(v)))

def in_band(rms):
    return rms is not None and a.lower <= rms <= a.upper

def frame_pass_rate(seq):
    return sum(1 for _, rms in seq if in_band(rms)) / len(seq) if seq else 0.0

def attempts(seq):
    """Сегментує кадри в попитки за розривом часу; повертає список попиток,
    кожна — список (ts,rms). Кадри всередині попитки впорядковані."""
    seq = sorted(seq)
    out, cur, last = [], [], None
    for ts, rms in seq:
        if last is not None and ts - last > a.gap:
            if cur: out.append(cur)
            cur = []
        cur.append((ts, rms)); last = ts
    if cur: out.append(cur)
    return out

def attempt_passes(att):
    """Попитка «жива» ⇔ є ≥ consecutive підряд кадрів у смузі."""
    run = 0
    for _, rms in att:
        run = run + 1 if in_band(rms) else 0
        if run >= a.consecutive:
            return True
    return False

print(f"Смуга (як у проді): {a.lower*1000:.0f}–{a.upper*1000:.0f} мм; "
      f"попитка = {a.consecutive} послідовних кадрів; розрив попиток > {a.gap} c\n")

bona = rows.get("bonafide", [])
attack_labels = [k for k in rows if k != "bonafide"]

# BONAFIDE
if bona:
    fr = 1 - frame_pass_rate(bona)
    atts = attempts(bona)
    at = 1 - (sum(attempt_passes(x) for x in atts) / len(atts) if atts else 0)
    print(f"BONAFIDE: кадрів {len(bona)}, попиток {len(atts)}")
    print(f"  BPCER frame-level   = {fr:.4f}")
    print(f"  BPCER attempt-level = {at:.4f}  (жива особа не пройшла попитку)\n")
else:
    print("⚠ Немає bonafide.\n")

# ATTACKS
worst_f = worst_a = 0.0
for lbl in sorted(attack_labels):
    seq = rows[lbl]
    fr = frame_pass_rate(seq)
    atts = attempts(seq)
    ar = sum(attempt_passes(x) for x in atts) / len(atts) if atts else 0.0
    worst_f = max(worst_f, fr); worst_a = max(worst_a, ar)
    print(f"ATTACK «{lbl}»: кадрів {len(seq)}, попиток {len(atts)}")
    print(f"  APCER frame-level   = {fr:.4f}")
    print(f"  APCER attempt-level = {ar:.4f}  (атака пройшла попитку)\n")

if attack_labels:
    print(f"Найгірший APCER: frame {worst_f:.4f}, attempt {worst_a:.4f}")

# Свіп ВЕРХНЬОГО порога (нижній фіксований) — вибір компромісу
print("\n— свіп верхнього порога (нижній = {:.0f} мм) —".format(a.lower*1000))
print("upper_mm  BPCER_frame  APCER_frame_max")
saved = a.upper
for up in [i/1000 for i in range(12, 41, 2)]:
    a.upper = up
    bp = (1 - frame_pass_rate(bona)) if bona else float("nan")
    am = max((frame_pass_rate(rows[l]) for l in attack_labels), default=float("nan"))
    print(f"{up*1000:6.0f}    {bp:.3f}        {am:.3f}")
a.upper = saved
