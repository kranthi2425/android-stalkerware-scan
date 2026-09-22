import json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from scanner import assess
class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.known=json.loads((ROOT/'iocs/packages.json').read_text())['packages']
    def test_public_ioc_packages_match(self):
        self.assertGreater(len(self.known),100)
        for pkg,families in self.known.items():
            r=assess({'package':pkg,'installer':'x'},self.known,set(),set(),set(),False,set())
            self.assertGreaterEqual(r['score'],100,(pkg,families))
    def test_privilege_combo(self):
        p={'package':'org.example.helper','installer':'com.android.packageinstaller'}
        perms={'android.permission.RECORD_AUDIO','android.permission.ACCESS_FINE_LOCATION','android.permission.READ_SMS'}
        r=assess(p,self.known,{p['package']},{p['package']},{p['package']},True,perms)
        self.assertGreaterEqual(r['score'],60)
    def test_benign_low(self):
        r=assess({'package':'org.example.notes','installer':'com.android.vending'},self.known,set(),set(),set(),False,set())
        self.assertEqual(r['score'],0)
if __name__=='__main__': unittest.main()
