import unittest


class CIGateProbe(unittest.TestCase):
    def test_intentional_failure(self):
        self.fail('Intentional branch-protection gate probe; do not merge')
