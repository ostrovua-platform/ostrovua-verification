#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
#  MiniFASNet (Silent-Face-Anti-Spoofing, Apache-2.0) → CoreML.
#  Безкоштовна passive anti-spoofing модель: 1 кадр обличчя → «живий/
#  підробка». Ловить друковане фото й відео-реплей за текстурою.
#
#  ЗАПУСК НА МАКУ (не в цій пісочниці — тут немає torch/ваг):
#     git clone https://github.com/minivision-ai/Silent-Face-Anti-Spoofing
#     cd Silent-Face-Anti-Spoofing
#     python3 -m venv venv && source venv/bin/activate
#     pip install torch torchvision coremltools opencv-python
#     # поклади цей файл у корінь репо й запусти:
#     python3 convert_antispoofing_model.py
#
#  Вихід: AntiSpoof27.mlmodel — додаси в Xcode-проєкт OstrovUA.
#
#  ⚠️ Препроцес МОДЕЛІ (звірити на вимірі): їх пайплайн кропить обличчя
#  зі scale=2.7 навколо bbox, ресайз 80×80, cv2-BGR, ToTensor → 0..1, CHW.
#  Тут задаємо ImageType BGR + scale=1/255. Якщо скор інвертований/дивний —
#  пришли вивід, підправимо (color_layout / порядок класів).
# ═══════════════════════════════════════════════════════════════════
import torch
import coremltools as ct
from src.anti_spoof_predict import AntiSpoofPredict

MODEL_PATH = "resources/anti_spoof_models/2.7_80x80_MiniFASNetV2.pth"
OUT        = "AntiSpoof27.mlmodel"

# Використовуємо ЇХ завантажувач (сам розбирає kernel/тип із назви файлу) —
# менше шансів помилитись з архітектурою. На Маку без CUDA піде на cpu.
predictor = AntiSpoofPredict(0)
predictor._load_model(MODEL_PATH)
model = predictor.model.eval()

# Модель віддає ЛОГІТИ [1,3] (softmax вони роблять окремо). Softmax
# застосуємо у Swift; конвертуємо як є.
example = torch.rand(1, 3, 80, 80)
with torch.no_grad():
    traced = torch.jit.trace(model, example)

mlmodel = ct.convert(
    traced,
    inputs=[ct.ImageType(
        name="input",
        shape=(1, 3, 80, 80),
        scale=1.0 / 255.0,               # ToTensor: 0..255 → 0..1
        bias=[0.0, 0.0, 0.0],
        color_layout=ct.colorlayout.BGR, # cv2 читає BGR
    )],
    outputs=[ct.TensorType(name="logits")],
    minimum_deployment_target=ct.target.iOS15,
    compute_units=ct.ComputeUnit.ALL,
)
mlmodel.short_description = "MiniFASNetV2 2.7 (Silent-Face-Anti-Spoofing, Apache-2.0). logits[3]: 0=spoof,1=real,2=spoof."
mlmodel.save(OUT)
print("✓ saved", OUT)
print("  вхід: input Image 80x80 BGR;  вихід: logits[3] (softmax у Swift; клас 1 = живий)")
print("  АТРИБУЦІЯ (Apache-2.0): додати згадку Minivision у ліцензіях застосунку.")
