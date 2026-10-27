"""
Security Console - Phase 0 Safety Net & Input Parser Fuzzing Tests
Validates that every parser of untrusted input handles malformed, huge, and empty input
without crashing the service.
"""
import os
import sys
import tempfile
import pathlib
import unittest

# Ensure isolated temporary SC_HOME before backend imports
_TEST_SC_HOME = tempfile.mkdtemp(prefix="sc_test_home_")
os.environ["SC_HOME"] = _TEST_SC_HOME

# Ensure backend can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

# Mock external web framework modules if not installed in current environment
from unittest.mock import MagicMock
for mod_name in ["uvicorn", "fastapi", "fastapi.responses", "fastapi.staticfiles", "pydantic", "psutil"]:
    try:
        __import__(mod_name)
    except ImportError:
        mock_mod = MagicMock()
        if mod_name == "pydantic":
            class MockBaseModel:
                pass
            mock_mod.BaseModel = MockBaseModel
        if mod_name == "fastapi":
            class MockHTTPException(Exception):
                def __init__(self, status_code=400, detail=""):
                    self.status_code = status_code
                    self.detail = detail
                    super().__init__(detail)
            mock_mod.HTTPException = MockHTTPException

            def pass_through_decorator(*args, **kwargs):
                return lambda fn: fn

            class MockApp:
                def post(self, *a, **k): return pass_through_decorator()
                def get(self, *a, **k): return pass_through_decorator()
                def delete(self, *a, **k): return pass_through_decorator()
                def on_event(self, *a, **k): return pass_through_decorator()
                def middleware(self, *a, **k): return pass_through_decorator()
                def mount(self, *a, **k): pass

            mock_mod.FastAPI = lambda *a, **k: MockApp()
        sys.modules[mod_name] = mock_mod

# Standalone test runner for parser resilience
class TestInputParsersSafetyNet(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    # 1. Zone.Identifier (MOTW) parser tests
    def test_motw_empty_and_missing(self):
        from main import read_motw
        self.assertFalse(read_motw("")["internet"])
        self.assertFalse(read_motw("non_existent_file_path_12345.xyz")["internet"])

    def test_motw_malformed_and_huge(self):
        from main import read_motw
        target = self.base / "test_file.exe"
        target.write_bytes(b"MZ" + b"\x00" * 100)
        
        # Test malformed stream
        stream = target.parent / (target.name + ":Zone.Identifier")
        try:
            with open(str(stream), "w", encoding="utf-8") as f:
                f.write("MalformedDataWithoutKeys\n" * 1000)
            res = read_motw(str(target))
            self.assertIsInstance(res, dict)
            self.assertFalse(res["internet"])
        except OSError:
            # Non-NTFS environments (or virtual filesystem)
            pass

    def test_motw_sanitization(self):
        from main import sanitize_url
        raw_url = "https://downloads.example.org/installer.exe?token=secret_abc123&auth=bearer_xyz&user=test"
        sanitized = sanitize_url(raw_url)
        self.assertNotIn("secret_abc123", sanitized)
        self.assertNotIn("bearer_xyz", sanitized)
        self.assertIn("[REDACTED]", sanitized)

    # 2. PE and Entropy parser tests
    def test_shannon_entropy_edge_cases(self):
        from main import shannon_entropy
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(shannon_entropy(b"A" * 10000), 0.0)
        # Uniform 256-byte distribution has entropy ~8.0
        uniform = bytes(range(256)) * 40
        self.assertAlmostEqual(shannon_entropy(uniform), 8.0, places=1)

    def test_analyze_pe_heuristics(self):
        from main import analyze_pe
        # Missing file
        res = analyze_pe("missing_file.exe")
        self.assertFalse(res["is_pe"])
        self.assertEqual(res["entropy"], 0.0)

        # Deceptive double extension
        target_deceptive = self.base / "Financial_Report.pdf.exe"
        target_deceptive.write_bytes(b"MZ" + b"\x90" * 500)
        res_dec = analyze_pe(str(target_deceptive))
        self.assertTrue(res_dec["is_pe"])
        self.assertTrue(res_dec["deceptive"])

        # Unicode Right-to-Left Override (RLO)
        target_rlo = self.base / "report\u202Eexe.pdf"
        target_rlo.write_bytes(b"MZ" + b"\x90" * 500)
        res_rlo = analyze_pe(str(target_rlo))
        self.assertTrue(res_rlo["rlo"])

    # 3. Authenticode parser tests
    def test_authenticode_edge_cases(self):
        from main import verify_authenticode
        self.assertFalse(verify_authenticode("")["valid"])
        self.assertFalse(verify_authenticode("missing_file.exe")["valid"])

        # Test system notepad catalog detection
        if os.name == "nt":
            notepad = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")
            if os.path.exists(notepad):
                sig = verify_authenticode(notepad)
                self.assertTrue(sig["valid"])
                self.assertTrue(sig["is_ms"])

    # 4. Multi-factor Risk Score tests
    def test_risk_score_calculation(self):
        from main import calculate_risk_score
        # Case A: High severity with untrusted internet download
        sig = {"valid": False, "is_ms": False}
        motw = {"internet": True}
        pe = {"packed": True, "deceptive": True, "rlo": False}
        res = calculate_risk_score("sigma", "high", r"C:\Users\User\Downloads\evil.pdf.exe", sig, motw, pe)
        self.assertGreaterEqual(res["score"], 80)
        self.assertEqual(res["level"], "critical")
        self.assertTrue(any(f["points"] == 30 for f in res["factors"]))

        # Case B: Verified Microsoft component should have negative trust discounts
        sig_ms = {"valid": True, "is_ms": True}
        motw_local = {"internet": False}
        pe_clean = {"packed": False, "deceptive": False, "rlo": False}
        res_ms = calculate_risk_score("sigma", "low", r"C:\Windows\System32\svchost.exe", sig_ms, motw_local, pe_clean)
        self.assertLessEqual(res_ms["score"], 20)

    # 5. MITRE ATT&CK mapping tests
    def test_mitre_mapping(self):
        from main import map_mitre
        self.assertIn("T1003", map_mitre("clamav", "Win.Tool.Mimikatz", ""))
        self.assertIn("T1486", map_mitre("yara", "Ransomware", "vssadmin delete shadows"))
        self.assertIn("T1059.001", map_mitre("sigma", "PowerShell", "iex (New-Object Net.WebClient)"))

    # 6. EICAR self-test detection
    def test_eicar_presence_in_self_test(self):
        import inspect
        from main import self_test
        src = inspect.getsource(self_test)
        self.assertIn("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", src)

    # 7. Bootstrap token authorization test for /api/auth/code
    def test_auth_code_requires_bootstrap_token(self):
        import main
        from unittest.mock import MagicMock
        
        # Unauthorized call without header
        req_unauth = MagicMock()
        req_unauth.headers = {}
        with self.assertRaises(main.HTTPException) as ctx:
            main.auth_code(req_unauth)
        self.assertEqual(ctx.exception.status_code, 403)

        # Unauthorized call with incorrect token
        req_bad = MagicMock()
        req_bad.headers = {"Authorization": "Bearer bad_token_12345"}
        with self.assertRaises(main.HTTPException) as ctx:
            main.auth_code(req_bad)
        self.assertEqual(ctx.exception.status_code, 403)

        # Authorized call with legitimate bootstrap token
        req_auth = MagicMock()
        req_auth.headers = {"Authorization": f"Bearer {main._BOOTSTRAP_TOKEN}"}
        res = main.auth_code(req_auth)
        self.assertIn("code", res)
        self.assertEqual(len(res["code"]), 16)

    # 8. Persistence hunts and MITRE mappings
    def test_persistence_hunts_and_mitre(self):
        from main import HUNTS
        self.assertIn("etc_hosts", HUNTS)
        self.assertIn("T1565.001", HUNTS["etc_hosts"]["mitre"])
        self.assertIn("T1547.001", HUNTS["startup_items"]["mitre"])
        self.assertIn("T1543.003", HUNTS["services"]["mitre"])

    # 9. Infostealer rules verification
    def test_infostealer_rules_presence(self):
        rule_file = pathlib.Path(__file__).parent.parent / "rules" / "yara" / "production_rules.yar"
        content = rule_file.read_text(encoding="utf-8")
        self.assertIn("SC_Infostealer_RedLine_Artifacts", content)
        self.assertIn("SC_Infostealer_Vidar_Artifacts", content)
        self.assertIn("SC_Infostealer_LummaC2_Patterns", content)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestInputParsersSafetyNet)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
