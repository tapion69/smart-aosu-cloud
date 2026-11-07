"""Pure signaling classifier tests; no credentials, network or HA imports."""
from pathlib import Path
import ast
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMP = ROOT / 'custom_components' / 'smart_aosu_cloud'
SOURCE = (COMP / 'tuya_mqtt_offer.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)
CLASSIFY_AST = next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
                    and n.name == '_signal_protocol_class')
NAMESPACE = {}
exec(compile(ast.Module(body=[CLASSIFY_AST], type_ignores=[]), '<classifier>', 'exec'), NAMESPACE)
classify = NAMESPACE['_signal_protocol_class']

class MqttClassificationTests(unittest.TestCase):
    def test_expected_sig_query_reply_does_not_count_as_sdp(self):
        self.assertEqual(classify(22), 'sigqry')
        self.assertEqual(classify(302), 'offer_answer')
        for value in (None, 0, 301, 303, 22.0, '22', True, {}, -1):
            with self.subTest(value=value):
                self.assertEqual(classify(value), 'other')

    def test_diagnostic_has_fixed_counters_and_no_wire_data(self):
        for token in ('reponses_sigqry', 'reponses_protocole_inattendu',
                      'messages_302_format_invalide','messages_302_autres_types'):
            self.assertIn(token, SOURCE)
        js=(COMP/'frontend'/'c9c-autonome-b1.js').read_text(encoding='utf-8')
        self.assertIn('sig.reponses_sigqry', js)
        self.assertNotIn('ptz_maintien', js)
        self.assertNotIn('msg.sdp', js)

if __name__ == '__main__':
    unittest.main()
