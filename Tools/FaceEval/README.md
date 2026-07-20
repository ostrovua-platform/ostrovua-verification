# FaceEval — вимірювання FAR/FRR моделі FaceEmbedding

Стенд рахує **False Accept Rate / False Reject Rate**, EER і ROC для
CoreML-моделі розпізнавання обличчя на стандартному датасеті пар
**LFW (Labeled Faces in the Wild)**. Препроцесинг ДОСЛІВНО повторює
застосунок (`FaceMatcher.alignedFace` + `FaceEmbedder`), тож числа
відображають реальний shipped-пайплайн, а не абстрактну модель.

Запускати на **macOS** (потрібні Vision + CoreML). Модель у репозиторій
не входить (45 МБ) — вказується шляхом; її SHA-256 — у `Provenance/MODEL.md`.

## 1. Отримати LFW

```
curl -LO https://vis-www.cs.umass.edu/lfw/lfw-deepfunneled.tgz
curl -LO https://vis-www.cs.umass.edu/lfw/pairs.txt
tar xzf lfw-deepfunneled.tgz          # → тека lfw-deepfunneled/<Ім'я>/<Ім'я>_0001.jpg
```

`pairs.txt` — офіційний протокол 10 фолдів × (300 genuine + 300 impostor)
= 6000 пар. Формат рядків: `Name idx1 idx2` (genuine) або
`Name1 idx1 Name2 idx2` (impostor).

## 2. Запуск

```
cd Tools/FaceEval
swift run -c release FaceEval \
  --model "$HOME/…/FaceEmbedding.mlpackage" \
  --lfw   ../../lfw-deepfunneled \
  --pairs ../../pairs.txt \
  --threshold 0.60 \
  --roc roc.csv
```

## 3. Вихід

```
═══ FAR/FRR (LFW) ═══
Валідних пар: genuine=…, impostor=…; face-detect errors=…
Робочий поріг (cosine ≥ 0.60):
   FAR = 0.xxxx
   FRR = 0.xxxx
EER ≈ 0.xxxx при порозі 0.xxx
AUC ≈ 0.xxxx
ROC → roc.csv
```

## 4. Що з цим робити

1. Вставити отримані FAR/FRR/EER/AUC у `Provenance/MODEL.md` і в
   відповідь аудитору (це і є «виміряна валідація моделі», аудит #9).
2. Якщо EER-поріг помітно відрізняється від 0.60 — переглянути
   `FaceMatcher.embeddingMatch` і задокументувати калібрування.
3. `face-detect errors` показує, на скількох фото Vision не знайшов
   обличчя (нормально для частини LFW); вони виключені з метрик.

## Межі

- LFW — «в дикій природі», не сценарій «селфі ↔ фото з чипа». Дає
  порівнянну з публікаціями базову оцінку. Доменні числа
  (селфі↔DG2) — окремий етап на власному наборі з згодами (privacy).
- Це FAR/FRR РОЗПІЗНАВАННЯ, не PAD. Стійкість до презентаційних
  атак міряється окремо — `Provenance/PAD_AND_BIOMETRIC_PLAN.md`.
