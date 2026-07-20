# Походження CoreML-моделі FaceEmbedding

- Файл: FaceEmbedding.mlpackage (не в репозиторії через розмір: 45M)
- Базова модель: FaceNet (конвертація: Tools/convert_face_model.py в основному проєкті)
- SHA-256 (усі файли пакета, відсортовані, конкатеновані):
  `04a4db780288799ebd2ee5ea79e5745ef25c7da03f1803ea4f9bb8585f5c4058`
- Перевірка на Маку:
  `find FaceEmbedding.mlpackage -type f | sort | xargs cat | shasum -a 256`

Відомі відкриті питання (аудит P0-04, чесно): іменований output tensor
не зафіксований у коді (береться featureNames.first), незалежна
біометрична оцінка FAR/FRR не проводилась. Це умови production-релізу,
не «зроблено».
