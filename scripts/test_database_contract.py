"""DeadZone schema checks without output of key material."""
import importlib.util
from pathlib import Path
import json
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("deadzone_database_audit", ROOT / "validate_deadzone_database.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class DatabaseContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        identity = {k: "example" for k in AUDIT.IDENTITY}
        identity["FINGERPRINT"] = "test/device/build:user/release-keys"
        for name, data in (
            ("pif-props.json", {**identity, "SECURITY_PATCH": "2026-10-05"}),
            ("app-props.json", {"com.example.game": identity}),
            ("device-props.json", {"devices": [identity]}),
            ("blacklist.json", ["com.example.hidden"]),
        ):
            (self.root / name).write_text(json.dumps(data))
        (self.root / "target-list.txt").write_text("com.example.gms#\n")
        (self.root / "keybox.xml").write_text("<AndroidAttestation></AndroidAttestation>")

    def test_valid_documents(self):
        report = AUDIT.audit(self.root)
        self.assertEqual(report["app_profiles"], 1)
        self.assertEqual(report["target_packages"], 1)
        self.assertEqual(report["keybox_xml_shape_checked"], 1)

    def test_invalid_patch_rejected(self):
        p = self.root / "pif-props.json"
        data = json.loads(p.read_text())
        data["SECURITY_PATCH"] = "2026-99-99"
        p.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            AUDIT.audit(self.root)

    def test_invalid_target_rejected(self):
        (self.root / "target-list.txt").write_text("com.example.gms??\n")
        with self.assertRaises(ValueError):
            AUDIT.audit(self.root)

    def test_keybox_is_never_in_report(self):
        (self.root / "keybox.xml").write_text("<AndroidAttestation><PrivateKey>PRIVATE-SENTINEL</PrivateKey></AndroidAttestation>")
        report = AUDIT.audit(self.root)
        self.assertNotIn("PRIVATE-SENTINEL", repr(report))

    def test_keybox_xml_root_is_checked(self):
        (self.root / "keybox.xml").write_text("<Unsafe/>")
        with self.assertRaises(ValueError):
            AUDIT.audit(self.root)


if __name__ == "__main__":
    unittest.main()