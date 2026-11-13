"""Only synthetic DEX instruction tests: no APK, camera, account or network."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from aosu_c9c_type4_route_offline import _native_p2p_skill, _type2_gate, _type4_gate, summarize


class SyntheticDex:
    def __init__(self):
        self.methods = [('', '') for _ in range(6000)]
        self.code = {}
        self.method_index = 100
        self.methods[5931] = ('Ltest/p2p/ThingSmartCameraP2PSync;', 'processCameraInfo')
        for index, name in ((3998, 'connect'), (4030, 'initNativeOnce'),
                            (4003, 'createDevice'), (4099, 'startPreview')):
            self.methods[index] = ('Ltest/ipccamerasdk/IPCThingP2PCamera;', name)
        self.words = {5931: [0] * 440, 3998: [0] * 580,
                      4030: [0] * 80, 4003: [0] * 210, 4099: [0] * 210}
        p = self.words[5931]
        p[133], p[134], p[135], p[163] = 0x4612, 0x6533, 30, 0x3828
        p[164], p[165], p[166] = 0x2612, 0x6533, 54
        p[311] = 0x090c

    def call(self, index, off, cls, name, regs=None):
        method_index = self.method_index
        self.method_index += 1
        self.methods[method_index] = ('Ltest' + cls, name)
        args = tuple(regs or (0,))
        word0 = 0x6e | (len(args) << 12)
        code2 = sum((r & 15) << (4 * i) for i, r in enumerate(args[:4]))
        if len(args) == 5:
            word0 |= (args[4] & 15) << 8
        self.words[index][off:off + 3] = [word0, method_index, code2]

    def finish(self):
        import struct
        self.code = {index: struct.pack(f'<{len(words)}H', *words)
                     for index, words in self.words.items()}
        return self


def fake_valid():
    d = SyntheticDex()
    p, c, init, create, preview = 5931, 3998, 4030, 4003, 4099
    for off, cls, name, regs in (
        (126, '/bean/CameraInfoBean;', 'getP2pSpecifiedType', (11,)),
        (136, '/bean/CameraInfoBean;', 'getId', (11,)),
        (140, '/bean/ConfigCameraBean;', 'setP2pId', (0, 5)),
        (149, '/bean/CameraInfoBean;', 'getP2PConfigStr', (11,)),
        (153, '/bean/ConfigCameraBean;', 'setToken', (0, 5)),
        (156, '/bean/CameraInfoBean;', 'getSkill', (11,)),
        (160, '/bean/ConfigCameraBean;', 'setSkill', (0, 5)),
        (167, '/bean/CameraInfoBean;', 'getP2pId', (11,)),
        (188, '/bean/CameraInfoBean;', 'getP2PConfigInitStr', (11,)),
        (308, '/alibaba/fastjson/JSON;', 'toJSONString', (11,)),
        (312, '/bean/ConfigCameraBean;', 'setConfigJson', (0, 9))
    ):
        d.call(p, off, cls, name, regs)
    for off, cls, name, regs in (
        (263, '/bean/ConfigCameraBean;', 'getConfigJson', (3,)),
        (279, '/api/ThingCameraInterface;', 'setCameraConfig', None),
        (302, '/api/ThingCameraInterface;', 'connect', None),
        (335, '/api/ThingCameraInterface;', 'connect', None),
        (360, '/api/ThingCameraInterface;', 'connect', None)
    ):
        d.call(c, off, cls, name, regs)
    d.call(create, 96, '/IPCThingP2PCamera;', 'initNativeOnce')
    d.call(init, 26, '/p2p/api/IThingP2P;', 'init')
    d.call(init, 68, '/api/ThingCameraEngineInterface;', 'initP2PModule')
    d.call(preview, 157, '/api/ThingCameraInterface;', 'startPreview')
    return d.finish()



def fake_skill_elf(value: int = 1635, *, machine: int = 183) -> bytes:
    """Four tiny ELF sections with a synthetic g_p2p_skill symbol."""
    blob = bytearray(1500)
    blob[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H', blob, 18, machine)
    struct.pack_into('<Q', blob, 40, 0x100)
    struct.pack_into('<HH', blob, 58, 64, 4)
    names = b'\x00g_p2p_skill\x00'
    blob[0x300:0x300+len(names)] = names
    # Section 1: dynstr
    struct.pack_into('<I', blob, 0x100+64+4, 3)
    struct.pack_into('<QQQ', blob, 0x100+64+16, 0, 0x300, len(names))
    # Section 2: dynsym linked to dynstr
    struct.pack_into('<I', blob, 0x100+128+4, 11)
    struct.pack_into('<QQQ', blob, 0x100+128+16, 0, 0x400, 48)
    struct.pack_into('<I', blob, 0x100+128+40, 1)
    struct.pack_into('<Q', blob, 0x100+128+56, 24)
    # Section 3: initialized data with virtual address distinct from file offset
    struct.pack_into('<I', blob, 0x100+192+4, 1)
    struct.pack_into('<QQQ', blob, 0x100+192+16, 0x160000, 0x500, 32)
    # Second symbol: name offset 1, section 3, initialized value at +4
    struct.pack_into('<IBBHQQ', blob, 0x400+24, 1, 0x11, 0, 3, 0x160004, 4)
    struct.pack_into('<I', blob, 0x504, value)
    return bytes(blob)


class TestNativeType4Route(unittest.TestCase):

    def test_native_named_skill_symbol_matches_verifiable_constant(self):
        self.assertEqual(_native_p2p_skill(fake_skill_elf()), 1635)
        self.assertNotEqual(_native_p2p_skill(fake_skill_elf(1636)), 1635)

    def test_native_skill_rejects_wrong_abi_or_bad_symbol_bounds(self):
        with self.assertRaises(ValueError):
            _native_p2p_skill(fake_skill_elf(machine=62))
        damaged = bytearray(fake_skill_elf())
        struct.pack_into('<Q', damaged, 0x400 + 24 + 8, 0x170000)
        with self.assertRaises(ValueError):
            _native_p2p_skill(bytes(damaged))

    def test_synthetic_complete_contract(self):
        report = summarize(fake_valid())
        self.assertEqual(len(report['facts']), 8)
        self.assertTrue(all(report['facts'].values()))
        self.assertFalse(report['video_confirmed'])
        self.assertFalse(report['camera_runtime_route_confirmed'])
        self.assertEqual(report['network_calls'], 0)
        self.assertEqual(report['camera_commands'], 0)
        self.assertFalse(report['user_secrets_or_ids_exported'])

    def test_type4_branch_never_inferred_from_type2(self):
        words = [0] * 230
        words[133], words[134], words[135], words[163] = 0x4612, 0x6533, 30, 0x3828
        words[164], words[165], words[166] = 0x2612, 0x6533, 54
        self.assertTrue(_type4_gate(tuple(words)))
        self.assertTrue(_type2_gate(tuple(words)))
        words[133] = 0x2612
        self.assertFalse(_type4_gate(tuple(words)))
        self.assertTrue(_type2_gate(tuple(words)))

    def test_missing_or_wrong_camera_info_serialization_fails(self):
        d = fake_valid()
        d.words[5931][308] = 0
        d.finish()
        self.assertFalse(summarize(d)['facts']['full_camera_info_serialized_to_config_json'])

    def test_missing_native_init_fails(self):
        d = fake_valid()
        d.words[4030][26] = 0
        d.finish()
        self.assertFalse(summarize(d)['facts']['native_initialization_present'])

    def test_missing_type4_token_fails(self):
        d = fake_valid()
        d.words[5931][153] = 0
        d.finish()
        self.assertFalse(summarize(d)['facts']['type4_uses_camera_info_token_and_skill'])

    def test_privacy_only_boolean_summary(self):
        r = summarize(fake_valid())
        self.assertEqual(set(r['facts'].values()), {True})
        self.assertNotIn('camera_id', str(r))
        self.assertNotIn('localKey', str(r))
        self.assertNotIn('sdp', str(r).lower())


if __name__ == '__main__':
    unittest.main()
