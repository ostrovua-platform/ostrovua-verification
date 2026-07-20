#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
#  Скоринг АКТИВНОЇ liveness (challenge-response, аудит #8).
#
#  Вхід: pad_challenge.csv (ChallengeLogger). Рядки-кадри
#  (timestamp,label,state,yaw,pitch,ear) + рядки-підсумки попиток
#  ATTEMPT_PASS / ATTEMPT_FAIL.
#
#  Метрика — на рівні ПОПИТКИ (єдино правильна для challenge-response):
#   BPCER = частка попиток bonafide, що НЕ пройшли челендж (жива особа
#           не змогла виконати послідовність) — має бути мала.
#   APCER = частка попиток атаки, що ПРОЙШЛИ челендж — має бути ~0 за
#           побудовою (фото/екран не змінюють позу й не відтворюють
#           випадкову послідовність).
#
#  Використання: python3 challenge_score.py pad_challenge.csv
# ═══════════════════════════════════════════════════════════════════
import csv, sys
from collections import defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else "pad_challenge.csv"
att = defaultdict(lambda: {"pass": 0, "fail": 0})
frames = defaultdict(int)

for r in csv.DictReader(open(path)):
    lbl = r["label"]; st = r["state"]
    if st == "ATTEMPT_PASS": att[lbl]["pass"] += 1
    elif st == "ATTEMPT_FAIL": att[lbl]["fail"] += 1
    else: frames[lbl] += 1

def rate(d):
    n = d["pass"] + d["fail"]
    return (d["pass"] / n if n else 0.0), n

print("Активна liveness (challenge-response) — на рівні попитки\n")

if "bonafide" in att:
    p, n = rate(att["bonafide"])
    print(f"BONAFIDE: попиток {n}, пройдено {att['bonafide']['pass']}")
    print(f"  BPCER = {1-p:.4f}  (жива особа НЕ пройшла — менше = краще)\n")
else:
    print("⚠ Немає bonafide-попиток.\n")

worst = 0.0
for lbl in sorted(k for k in att if k != "bonafide"):
    p, n = rate(att[lbl])
    worst = max(worst, p)
    print(f"ATTACK «{lbl}»: попиток {n}, пройшли челендж {att[lbl]['pass']}")
    print(f"  APCER = {p:.4f}  (атака пройшла — менше = краще)")

if any(k != "bonafide" for k in att):
    print(f"\nНайгірший APCER атак = {worst:.4f}")
    print("Ціль: APCER = 0 (жодна статична атака не проходить челендж),"
          " BPCER малий (жива особа проходить зручно).")

print(f"\nКадрів усього: {sum(frames.values())} (для калібрування порогів пози/EAR)")
