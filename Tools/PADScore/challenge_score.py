#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
#  Скоринг АКТИВНОЇ liveness (challenge-response, аудит #8) — з
#  ДОВІРЧИМИ ІНТЕРВАЛАМИ (Wilson score, 95%).
#
#  Вхід: pad_challenge.csv (ChallengeLogger). Рядки-кадри
#  (timestamp,label,state,yaw,pitch,ear) + рядки-підсумки попиток
#  ATTEMPT_PASS / ATTEMPT_FAIL.
#
#  Метрика — на рівні ПОПИТКИ (єдино правильна для challenge-response):
#   BPCER = частка попиток bonafide, що НЕ пройшли челендж (жива особа
#           не змогла виконати послідовність) — має бути мала.
#   APCER = частка попиток атаки, що ПРОЙШЛИ челендж — ціль ~0.
#
#  ЧОМУ CI: APCER=0 на 1 попитці НЕ доводить нічого. За «правилом трьох»
#  0 успіхів на n спроб дає лише верхню межу ≈ 3/n. Щоб ЧЕСНО заявити
#  «APCER ≤ 5%», треба ~60 атак поспіль без жодного проходу. Скрипт
#  друкує досягнуту верхню межу і скільки ще спроб треба до цілі.
#
#  Використання:
#     python3 challenge_score.py pad_challenge.csv [--target 0.05]
#  Залежностей немає (Wilson рахується вручну, без scipy).
# ═══════════════════════════════════════════════════════════════════
import csv, sys, math
from collections import defaultdict

Z = 1.959963985  # 95% двобічний

def wilson(k, n, z=Z):
    """Wilson score interval для частки k/n. Повертає (p̂, lo, hi)."""
    if n == 0:
        return 0.0, 0.0, 1.0
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return p, max(0.0, center - half), min(1.0, center + half)

def attempts_for_upper(target, z=Z):
    """Мінімум n, щоб при 0 успіхів верхня межа Wilson ≤ target."""
    n = 1
    while n < 100000:
        _, _, hi = wilson(0, n, z)
        if hi <= target:
            return n
        n += 1
    return None

def parse(path):
    att = defaultdict(lambda: {"pass": 0, "fail": 0})
    frames = defaultdict(int)
    feats = defaultdict(lambda: {"glare": [], "hf": [], "depth": []})   # анти-реплей ознаки
    with open(path) as f:
        for r in csv.DictReader(f):
            lbl, st = r["label"], r["state"]
            if st == "ATTEMPT_PASS":   att[lbl]["pass"] += 1
            elif st == "ATTEMPT_FAIL": att[lbl]["fail"] += 1
            else:
                frames[lbl] += 1
                for k in ("glare", "hf", "depth"):
                    v = (r.get(k) or "").strip()
                    if v:
                        try: feats[lbl][k].append(float(v))
                        except ValueError: pass
    return att, frames, feats

def _pct(xs, p):
    if not xs: return None
    s = sorted(xs); i = min(len(s) - 1, max(0, int(round(p / 100 * (len(s) - 1)))))
    return s[i]

def report_features(feats):
    labels = [l for l in feats if any(feats[l][k] for k in ("glare", "hf", "depth"))]
    if not labels:
        return
    print("─── Сигнали анти-реплею (стенд, сирі ознаки по кадрах) ───")
    print("    Мета: bonafide і screen/photo мають РОЗДІЛЯТИСЬ. Якщо ні —")
    print("    сигнал не годиться (як depth-RMS). Довіряємо лише за розділенням.\n")
    for k, name in (("glare", "глар (частка білих)"), ("hf", "муар/висока частота"), ("depth", "рельєф глибини")):
        rows = [(l, feats[l][k]) for l in labels if feats[l][k]]
        if not rows:
            continue
        print(f"  {name}:")
        for l, xs in sorted(rows):
            print(f"    {l:10} n={len(xs):<5} медіана={_pct(xs,50):.4f}  "
                  f"p10={_pct(xs,10):.4f}  p90={_pct(xs,90):.4f}")
        # груба ознака розділення: медіана bonafide vs медіана атак
        if "bonafide" in dict(rows):
            bmed = _pct(dict(rows)["bonafide"], 50)
            for l, xs in rows:
                if l != "bonafide":
                    amed = _pct(xs, 50)
                    gap = abs(bmed - amed)
                    print(f"      Δмедіан bonafide↔{l} = {gap:.4f}")
        print()

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = args[0] if args else "pad_challenge.csv"
    target = 0.05
    if "--target" in sys.argv:
        target = float(sys.argv[sys.argv.index("--target") + 1])

    att, frames, feats = parse(path)
    print("═══ Активна liveness (challenge-response) — на рівні попитки ═══")
    print(f"    Довірчі інтервали: Wilson score, 95%.  Ціль APCER-межі: {target:.0%}\n")

    # ── BONAFIDE (BPCER) ────────────────────────────────────────────
    if "bonafide" in att:
        d = att["bonafide"]; n = d["pass"] + d["fail"]; fails = d["fail"]
        p, lo, hi = wilson(fails, n)                    # BPCER = частка фейлів
        print(f"BONAFIDE:  попиток {n},  пройдено {d['pass']},  фейлів {fails}")
        print(f"  BPCER = {p:.3f}   95% CI [{lo:.3f}, {hi:.3f}]   (менше = краще)")
        if n < 20:
            print(f"  ⚠ n<20 — інтервал широкий; для BPCER з довірою треба ≥20–30 попиток.")
        print()
    else:
        print("⚠ Немає bonafide-попиток.\n")

    # ── АТАКИ (APCER на клас) ────────────────────────────────────────
    attack_labels = sorted(k for k in att if k != "bonafide")
    worst_hi = 0.0
    if not attack_labels:
        print("⚠ Немає попиток-атак (photo/screen/...).")
    for lbl in attack_labels:
        d = att[lbl]; n = d["pass"] + d["fail"]; passes = d["pass"]
        p, lo, hi = wilson(passes, n)                   # APCER = частка проходів
        worst_hi = max(worst_hi, hi)
        print(f"ATTACK «{lbl}»:  попиток {n},  пройшли челендж {passes}")
        print(f"  APCER = {p:.3f}   95% CI [{lo:.3f}, {hi:.3f}]   верхня межа = {hi:.1%}")
        if passes == 0:
            need = attempts_for_upper(target)
            if n < need:
                print(f"  → 0 проходів. Щоб заявити APCER ≤ {target:.0%} (95%), "
                      f"треба {need} попиток без проходу: ще {need - n}.")
            else:
                print(f"  ✓ 0 проходів на {n} попиток → APCER ≤ {target:.0%} (95%) ДОСЯГНУТО.")
        else:
            print(f"  ✗ АТАКА ПРОЙШЛА {passes}× — це не 0. Розбирати кадри цих попиток.")
        print()

    # ── Підсумок ────────────────────────────────────────────────────
    print("─── Підсумок ───")
    if attack_labels:
        print(f"Найгірша верхня межа APCER по атаках = {worst_hi:.1%}")
        n_target = attempts_for_upper(target)
        print(f"Орієнтир збору: {n_target} попиток на КОЖЕН клас атаки (0 проходів) "
              f"→ APCER ≤ {target:.0%}; + ≥20–30 bonafide для BPCER.")
    total_att = sum(d['pass'] + d['fail'] for d in att.values())
    print(f"Усього попиток: {total_att}.  Кадрів: {sum(frames.values())} "
          f"(для калібрування порогів пози/EAR).\n")

    report_features(feats)   # ── сигнали анти-реплею: муар/глар/depth ──

    print("Чесно: точкова оцінка APCER=0 нічого не доводить без n. "
          "Заявляємо лише ту верхню межу, яку підтверджує зібране n. "
          "Сигнал анти-реплею довіряємо лише якщо bonafide↔screen розділяються.")

if __name__ == "__main__":
    main()
