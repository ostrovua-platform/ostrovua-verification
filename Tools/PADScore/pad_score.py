#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
#  PAD-скоринг (аудит #8): рахує APCER / BPCER із зібраного pad_log.csv.
#
#  Вхід: CSV з застосунку (DEBUG PADLogger) — колонки timestamp,label,rms_m.
#   label: bonafide (жива особа) або тип атаки (print/screen/mask/other).
#   rms_m: виміряний RMS-залишок глибини (метри); nil — кадр без валідної глибини.
#
#  Поріг рішення застосунку: RMS ≥ 0.005 м → кадр «живий».
#
#  Метрики (ISO/IEC 30107-3, наближення на рівні кадрів):
#   APCER (на клас атаки) = частка кадрів атаки, що ПРОЙШЛИ поріг
#     (сприйняті як живі) — чим менше, тим краще.
#   BPCER = частка кадрів bonafide, що НЕ пройшли поріг
#     (жива особа відхилена) — чим менше, тим краще.
#
#  Використання:
#    python3 pad_score.py pad_log.csv [--threshold 0.005]
# ═══════════════════════════════════════════════════════════════════
import csv, sys, argparse
from collections import defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("csv")
ap.add_argument("--threshold", type=float, default=0.005)
a = ap.parse_args()

frames = defaultdict(list)   # label -> [rms|None]
with open(a.csv) as f:
    for row in csv.DictReader(f):
        v = row["rms_m"].strip()
        frames[row["label"]].append(None if v == "nil" else float(v))

def passed(vals, t):   # кадр «живий», якщо RMS є і ≥ поріг
    return sum(1 for v in vals if v is not None and v >= t)

t = a.threshold
print(f"Поріг рішення: RMS ≥ {t} м\n")

bona = frames.get("bonafide", [])
if bona:
    live = passed(bona, t)
    bpcer = 1 - live / len(bona)
    print(f"BONAFIDE: кадрів {len(bona)}, пройшли {live}")
    print(f"  BPCER = {bpcer:.4f}  (жива особа відхилена — менше = краще)\n")
else:
    print("⚠ Немає кадрів bonafide — зніми живу особу.\n")

attack_labels = [k for k in frames if k != "bonafide"]
worst = 0.0
for lbl in sorted(attack_labels):
    vals = frames[lbl]
    ap_ = passed(vals, t) / len(vals) if vals else 0.0
    worst = max(worst, ap_)
    print(f"ATTACK «{lbl}»: кадрів {len(vals)}, пройшли поріг {passed(vals, t)}")
    print(f"  APCER = {ap_:.4f}  (атака пройшла як жива — менше = краще)")

if attack_labels:
    print(f"\nНайгірший APCER серед атак = {worst:.4f}")
    print("Ціль high-assurance: APCER мінімальний при прийнятному BPCER;")
    print("порогом можна рухати компроміс (свіп нижче).")

# Свіп порога для вибору компромісу
print("\n— свіп порога —")
print("thr_mm  BPCER   APCER_max")
ts = [i / 1000 for i in range(2, 13)]   # 2..12 мм
for tt in ts:
    bp = (1 - passed(bona, tt) / len(bona)) if bona else float("nan")
    am = max((passed(frames[l], tt) / len(frames[l])) for l in attack_labels) if attack_labels else float("nan")
    print(f"{tt*1000:5.0f}   {bp:.3f}   {am:.3f}")
