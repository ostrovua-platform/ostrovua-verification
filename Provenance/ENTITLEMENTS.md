# Пояснення до OstrovUA.entitlements

- `com.apple.developer.devicecheck.appattest-environment = production`
  — задано ЯВНО: усі збірки (включно з dev-signed) атестуються проти
  production-серверів Apple App Attest; сервер приймає лише
  production-атестації (`APPATTEST_ENV=production`, fail-closed до
  будь-яких інших значень).
- `aps-environment = development` у файлі — НЕ суперечність:
  це значення перезаписується Xcode при підписанні (dev-збірка →
  development APNs, TestFlight/App Store → production APNs).
  Сервер пушів тримає обидва APNs-хости і маршрутизує за
  environment токена пристрою.
