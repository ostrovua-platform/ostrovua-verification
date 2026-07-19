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
# очікування: тіла запитів — challenge/attest-ключі та {method, challengeId}
```

**3. Структура PassportData ніде не серіалізується:**

```bash
grep -rn "PassportData" Sources | grep -i "encode\|json\|codable"
# очікування: порожньо — структура не Codable, серіалізувати її нічим
```

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
  `FaceEmbedder.swift` показує, як вона використовується, з фолбеком
  на Vision `VNFeaturePrint`.
- Читання чипа — бібліотека [NFCPassportReader](https://github.com/AndyQ/NFCPassportReader) (MIT).
- Passive Authentication (перевірка підпису даних чипа за CSCA-сертифікатами)
  — у беті ще не увімкнена; заплановано. Це вплине на стійкість до
  підроблених чипів, але не на приватність — модель даних не зміниться.
