# Чек-лист аудиту (відтворюваний)

Кожне твердження README можна перевірити командою з кореня репозиторію.

**1. Паспортні дані не пишуться на диск і не логуються:**

```bash
grep -rn "UserDefaults\|Keychain\|FileManager\|write(to\|jpegData\|pngData\|print(\|NSLog\|Logger" Sources/Verification
# очікування: порожньо
```

**2. Мережеві виклики — лише в Attestation, і жодного поля документа:**

```bash
grep -rn "URLRequest\|URLSession" Sources/Verification
# очікування: порожньо (уся мережа — в Sources/Attestation)

grep -rn "httpBody" Sources/Attestation
# очікування: challenge/attest-ключі та канонічний payload approve:
# enum-результати + sod (EF.SOD: хеші DG + сертифікат + підпис держави,
# БЕЗ персональних полів) + dgHashes. Жодного поля документа.
# Серверна перевірка SOD — Server/passiveauth.js (Passive Authentication).
```

**3. Структура PassportData ніде не серіалізується у цьому модулі:**

```bash
grep -rn "PassportData" Sources | grep -i "JSONSerialization\|JSONEncoder\|httpBody"
# очікування: порожньо
# ЗАСТЕРЕЖЕННЯ: те, що PassportData не Codable, НЕ доводить неможливість
# серіалізації — її поля можна вручну покласти в JSONSerialization.
# Ця перевірка показує лише, що В ЦЬОМУ МОДУЛІ такого немає. Повний
# доказ потребує аудиту всього застосунку (CurrentSession, API-клієнт).

**4. Фото з чипа (DG2) використовується лише для локальної звірки:**

```bash
grep -rn "chipPhoto\|passportImage" Sources
# очікування: NFCVerificationManager (читання) → FaceMatcher (порівняння). Все.
```

**5. Серверна частина** — обробник `approve` наведено дослівно в
`docs/server-side.md`; у схемі бази немає колонок під дані документа.

## Відомі архітектурні рішення (щоб не шукати «баги» там, де їх немає)

- Репозиторій — довідковий зріз модуля з робочого застосунку:
  залежить від внутрішніх компонентів (локалізація `trs()`, палітра,
  `AuthStore`) і не збирається окремо. Мета — аудит, не переиспользование.
- CoreML-модель ембеддингів обличчя (`FaceEmbedding.mlpackage`,
  конвертований FaceNet) у репозиторій не включена через розмір (45 МБ);
  її SHA-256 і спосіб перевірки — `Provenance/MODEL.md`. Fallback на
  Vision `VNFeaturePrint` ЗАБОРОНЕНИЙ у release (DEBUG-only,
  `FaceMatcher.swift`): без моделі верифікація не проходить.
- Читання чипа — бібліотека [NFCPassportReader](https://github.com/AndyQ/NFCPassportReader)
  (MIT), версія закріплена у `Provenance/Package.resolved` (2.3.2).
- Passive Authentication — реалізована СЕРВЕРНО: `Server/passiveauth.js`
  (перевірка підпису SOD, ланцюжок DSC→CSCA України, звірка хешів DG).
  Режим розкатки: `PA_ENFORCE=0` (лог) → `PA_ENFORCE=1` (жорстко).
  Клони чипів (той самий SOD) PA не ловить — див. threat-model.md.
