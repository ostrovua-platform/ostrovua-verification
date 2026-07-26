import os
import sys
import unittest
from pathlib import Path


SERVICE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE))


@unittest.skipUnless(os.environ.get("BIOMETRIC_MODEL_DIR"), "pinned models are required")
class ModelSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import cv2
        from engine import BiometricEngine

        fixtures = os.environ.get("SILENT_FACE_FIXTURE_DIR")
        if not fixtures:
            raise unittest.SkipTest("SILENT_FACE_FIXTURE_DIR is required")
        cls.cv2 = cv2
        cls.engine = BiometricEngine.from_environment()
        cls.fixtures = Path(fixtures)

    def pad_score(self, name):
        image = self.cv2.imread(str(self.fixtures / name))
        self.assertIsNotNone(image)
        image, face = self.engine._detect_one(image, name)
        return self.engine._pad_score(image, face)

    def test_pinned_model_set_loads(self):
        self.assertRegex(self.engine.model_set_hash, r"^[0-9a-f]{64}$")
        self.assertFalse(self.engine.calibration_approved)

    def test_upstream_live_fixture_separates_from_print_and_screen_spoofs(self):
        live = self.pad_score("image_T1.jpg")
        print_spoof = self.pad_score("image_F1.jpg")
        screen_spoof = self.pad_score("image_F2.jpg")
        self.assertGreater(live, 0.90)
        self.assertLess(print_spoof, 0.50)
        self.assertLess(screen_spoof, 0.50)
        self.assertGreater(live - max(print_spoof, screen_spoof), 0.50)


if __name__ == "__main__":
    unittest.main()
