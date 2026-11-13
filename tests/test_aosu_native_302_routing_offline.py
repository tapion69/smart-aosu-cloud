"""Offline regression of genuine Thing 302 LAN/MQTT routing interpretation.

Synthetic DEX method bytes and synthetic ELF export tables only.
The proprietary AOSU APK is NEVER uploaded to GitHub Actions.
"""
import ast
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT/'tools'/'aosu_native_302_routing_offline.py').read_text('utf-8')
TREE = ast.parse(SOURCE)
DEFS = [n for n in TREE.body if isinstance(n, ast.FunctionDef)
        and n.name in ('_read_elf_dynsyms','_check_thing_send302_gate',
                       'summarize')]
EXPORTS = {
    "native_mqtt_bridge": "_ZN16ThingSmartP2PSDK22SendMessageThroughMQTTEPcS0_j",
    "native_lan_bridge": "_ZN16ThingSmartP2PSDK21SendMessageThroughLANEPcS0_j",
    "native_connection_v3": "ThingP2PConnect_v3",
    "native_http_callback": "ThingP2PSetHttpResult",
    "native_signaling_callback": "ThingP2PSetSignaling",
}
N = {'struct':struct,'DexIndex':object,'_REQUIRED_EXPORTS':EXPORTS}
exec(compile(ast.Module(body=DEFS, type_ignores=[]),
             '<only_static_functions>', 'exec'),N)


class FakeDex:
    def method(self, cls, fn):
        if fn == 'send302MessageThroughMqtt':
            words = [0] * 75
            words[44] = 0x0838
            words[45] = 11
            return struct.pack('<75H', *words)
        if fn == 'sendMessageThroughMqtt':
            return b'\x11\x22'
        return b''
    def calls(self, source, cls, name):
        return name in ('send302MessageThroughMqtt','getDeviceBean',
                        'getPv','getLocalKey','lan302Publish','publish')


class TestP2P302Route(unittest.TestCase):
    def test_literal_if_eqz_v8_branches_to_mqtt(self):
        words = [0] * 75
        words[44] = 0x0838
        words[45] = 11
        f = N['_check_thing_send302_gate'](tuple(words))
        self.assertTrue(f['branche_lan_verifiee'])
        self.assertTrue(f['branche_mqtt_verifiee'])
        words[45] = 10
        self.assertFalse(all(N['_check_thing_send302_gate'](tuple(words)).values()))
        words[44] = 0x0938
        words[45] = 11
        self.assertFalse(all(N['_check_thing_send302_gate'](tuple(words)).values()))
        self.assertFalse(all(N['_check_thing_send302_gate']((0,0)).values()))

    def test_sdk_evidence_reports_no_native_equivalence(self):
        r = N['summarize'](FakeDex(),set(EXPORTS.values()))
        self.assertTrue(all(r['faits'].values()))
        self.assertFalse(r['parite_protocole_thing4_prouvee'])
        self.assertFalse(r['camera_c9c_identifiee'])
        self.assertFalse(r['offre_native_observee'])
        self.assertFalse(r['executable_sur_home_assistant_x86_64'])
        self.assertEqual(r['appels_reseau'],0)
        self.assertEqual(r['actions_camera'],0)
        self.assertFalse(r['identifiants_et_secrets_retournes'])
        self.assertEqual(len(r['faits']),13)

    def test_partial_callback_not_reported_as_complete(self):
        r = N['summarize'](FakeDex(), {'ThingP2PSetSignaling'})
        self.assertFalse(r['faits']['native_mqtt_bridge'])
        self.assertFalse(r['faits']['native_lan_bridge'])
        self.assertTrue(r['faits']['native_signaling_callback'])
        self.assertFalse(r['parite_protocole_thing4_prouvee'])

    def test_elf_symbols_can_be_read_without_loading_vendor_code(self):
        data=bytearray(1800)
        data[:6]=b'\x7fELF\x02\x01'
        struct.pack_into('<H',data,18,183)
        struct.pack_into('<Q',data,0x28,0x100)
        struct.pack_into('<H',data,0x3A,64)
        struct.pack_into('<H',data,0x3C,3)
        string_data=b'\x00ThingP2PConnect_v3\x00OTHER_UNTRUSTED\x00'
        data[0x300:0x300+len(string_data)]=string_data
        # section 1 = linked string table
        off1=0x100+64
        struct.pack_into('<I',data,off1+4,3)
        struct.pack_into('<Q',data,off1+0x18,0x300)
        struct.pack_into('<Q',data,off1+0x20,len(string_data))
        # section 2 = dynsym
        off2=0x100+128
        struct.pack_into('<I',data,off2+4,11)
        struct.pack_into('<Q',data,off2+0x18,0x400)
        struct.pack_into('<Q',data,off2+0x20,48)
        struct.pack_into('<I',data,off2+0x28,1)
        struct.pack_into('<Q',data,off2+0x38,24)
        struct.pack_into('<I',data,0x400+24,1)
        names=N['_read_elf_dynsyms'](bytes(data))
        self.assertEqual(names,{'ThingP2PConnect_v3'})
        self.assertNotIn('OTHER_UNTRUSTED',json.dumps(names))

    def test_private_apk_never_committed_or_called_from_ci(self):
        self.assertIn('hashlib.sha256(raw_archive)',SOURCE)
        self.assertIn('split_config.arm64_v8a.apk',SOURCE)
        self.assertNotIn('requests.',SOURCE)
        self.assertNotIn('mqtt_publish(',SOURCE)
        self.assertNotIn('socket.',SOURCE)


if __name__=='__main__':
    unittest.main()
