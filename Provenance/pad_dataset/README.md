# Сирий PAD-датасет (анонімізований)

`pad_log_2026-07-20.csv` — виміряний depth-RMS кожного кадру першого
PAD-прогону (аудит #8). Колонки: `t_rel_s` (час від старту, с — без
абсолютних міток), `label` (bonafide/print/screen), `rms_m` (RMS у
метрах). Жодних зображень, імен чи персональних даних — лише числа.

Відтворити метрики:
`python3 ../../Tools/PADScore/pad_score.py pad_log_2026-07-20.csv`

Джерело кадрів: `PADLogger.swift` (DEBUG), той самий вимір, що й
бойовий gate `FaceLivenessManager.depthRMS`.
