"""AOSU getInfoBySn CP ID: use existing read, never guess/serialize IDs."""
from __future__ import annotations

import ast
import json
import runpy
import time
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMP = ROOT / "custom_components" / "smart_aosu_cloud"
MODULE = COMP / "c9c_cp_detail_identity.py"
CP = runpy.run_path(str(COMP / "c9c_cp_reference_b32.py"))
TOPO = runpy.run_path(str(COMP / "camera_topology.py"))
CODE = MODULE.read_text(encoding="utf-8")
TREE = ast.parse(CODE)
FUNCS = [node for node in TREE.body if isinstance(node, ast.FunctionDef)]
NS = {
    "time": time, "Any": object,
    "extract_c9c_cp_reference": CP["extract_c9c_cp_reference"],
    "_valid_reference": CP["_valid_reference"],
}
exec(compile(ast.Module(body=FUNCS,type_ignores=[]),
             str(MODULE),"exec"), NS)
extract = NS["extract_cp_id_from_aosu_detail"]
remember = NS["remember_cp_id_from_aosu_detail"]
resolve = NS["resolve_aosu_cp_device_id"]
SN = "AOSU_SYNTHETIC_SERIAL"
CPID = "TUYA_SYNTHETIC_DEVICE_ID"
SID = "AOSU_SYNTHETIC_SID"
UID = "AOSU_SYNTHETIC_UID"


def details(*, sn=SN, cp=CPID, field="cpDeviceId"):
    return {"errno":0,"data":{"sn":sn,field:cp}}


def fake_client():
    return SimpleNamespace(
        _sid=SID,_uid=UID,_standalone_c9c_sn=SN,
        _standalone_c9c_coop_id=None,
        _standalone_c9c_cp_detail=None,
    )


class TestVerifiedCPDetail(unittest.TestCase):
    def test_exact_sn_cp_root_is_used(self):
        self.assertEqual(extract(details(),SN),
                         (CPID,"cp_device_id_detail_sn_verifie"))

    def test_exact_sn_coop_uuid_and_nested_cp_are_equivalent_sdk_sources(self):
        for payload in (
            details(field="coopUUID"),
            {"errno":0,"data":{"sn":SN,"cpDeviceInfo":{"cpDeviceId":CPID}}},
            {"errno":0,"data":{"list":[{"sn":SN,"coopUUID":CPID}]}},
        ):
            with self.subTest(payload=payload):
                self.assertEqual(extract(payload,SN)[0],CPID)

    def test_different_sn_cannot_reuse_reference(self):
        self.assertEqual(extract(details(sn="OTHER_AOSU_SN"),SN),
                         (None,"numero_serie_contradictoire"))

    def test_multiple_serials_are_contradictory_even_if_one_matches(self):
        x={"errno":0,"data":{"list":[
            {"sn":SN,"cpDeviceId":CPID},
            {"sn":"OTHER_AOSU_SN","cpDeviceId":"OTHER_CP_ID"}
        ]}}
        self.assertEqual(extract(x,SN),(None,"numero_serie_contradictoire"))

    def test_different_cp_values_for_same_sn_are_contradictory(self):
        x={"errno":0,"data":{"list":[
            {"sn":SN,"cpDeviceId":CPID},
            {"sn":SN,"cpDeviceId":"OTHER_CP_ID"}
        ]}}
        self.assertEqual(extract(x,SN),(None,"cp_device_id_contradictoire"))

    def test_same_row_root_and_nested_conflicting_cp_rejected(self):
        x={"errno":0,"data":{"sn":SN,"coopUUID":"FIRST_REF",
                              "cpDeviceInfo":{"cpDeviceId":"SECOND_REF"}}}
        self.assertEqual(extract(x,SN),(None,"cp_device_id_contradictoire"))

    def test_missing_and_bad_cp_is_not_fabricated_from_device_id(self):
        for row,source in (
            ({"sn":SN,"deviceId":CPID},"cp_device_id_absent_du_detail"),
            ({"sn":SN,"cpUuid":CPID},"cp_device_id_absent_du_detail"),
            ({"sn":SN,"uuid":CPID},"cp_device_id_absent_du_detail"),
            ({"sn":SN,"cpDeviceId":" BAD REF"},"cp_device_id_contradictoire"),
        ):
            with self.subTest(row=row):
                self.assertEqual(extract({"errno":0,"data":row},SN),
                                 (None,source))

    def test_refused_bad_structure_missing_sn_cannot_authorize(self):
        self.assertEqual(extract({"errno":1,"data":{"sn":SN,"cpDeviceId":CPID}},SN)[0],None)
        self.assertEqual(extract({"errno":0,"data":{"cpDeviceId":CPID}},SN),
                         (None,"numero_serie_absent"))
        self.assertEqual(extract({},SN)[0],None)
        self.assertEqual(extract({"errno":0,"data":"secret"},SN)[0],None)

    def test_transient_detail_cp_is_usable_by_typed_video_selector(self):
        c=fake_client()
        self.assertEqual(remember(c,details(),SN),"cp_device_id_detail_sn_verifie")
        self.assertEqual(resolve(c),(CPID,"detail_sn_session"))
        selected=TOPO["select_tuya_standalone_target_typed"](
            {CPID:{"devId":CPID}},
            camera_sn=SN,camera_cp_device_id=resolve(c)[0])
        self.assertEqual(selected,(CPID,"identite_exacte_cp_device_id_dev_id"))

    def test_readonly_detail_from_another_session_is_rejected(self):
        c=fake_client();remember(c,details(),SN)
        for field,invalid in (("_sid","OTHER_SESSION"),
                              ("_uid","OTHER_USER"),
                              ("_standalone_c9c_sn","OTHER_CAMERA")):
            current=getattr(c,field)
            setattr(c,field,invalid)
            self.assertEqual(resolve(c),(None,"aucune"))
            setattr(c,field,current)

    def test_expired_detail_reference_is_not_used(self):
        c=fake_client();remember(c,details(),SN)
        c._standalone_c9c_cp_detail["created"]=time.monotonic()-3601
        self.assertEqual(resolve(c),(None,"aucune"))

    def test_valid_getlist_and_detail_agree(self):
        c=fake_client()
        c._standalone_c9c_coop_id=CPID
        remember(c,details(),SN)
        self.assertEqual(resolve(c),(CPID,"getlist_sn"))

    def test_getlist_detail_conflict_blocks_video(self):
        c=fake_client()
        c._standalone_c9c_coop_id="OTHER_CP_ID"
        remember(c,details(),SN)
        self.assertEqual(resolve(c),(None,"sources_aosu_contradictoires"))

    def test_failed_detail_clears_previous_verified_cp(self):
        c=fake_client()
        remember(c,details(),SN)
        self.assertEqual(resolve(c)[0],CPID)
        remember(c,{"errno":1,"data":details()["data"]},SN)
        self.assertEqual(resolve(c),(None,"aucune"))

    def test_no_secret_identifiers_in_status_or_exceptions(self):
        c=fake_client()
        source=remember(c,details(),SN)
        report=json.dumps({"cp_device_id_detail_source":source,
                           "resolution":resolve(c)[1]})
        for secret in (SN,CPID,SID,UID):
            self.assertNotIn(secret,report)

    def test_existing_detail_read_is_reused_no_extra_network_or_camera(self):
        probe=(COMP/"c9c_detail_probe.py").read_text()
        self.assertIn("remember_cp_id_from_aosu_detail(client, parsed, sn)",probe)
        self.assertIn('report["cp_device_id_detail_source"] = cp_source',probe)
        self.assertIn("getInfoBySn",probe)
        self.assertNotIn("import requests",CODE)
        self.assertNotIn(".post(",CODE)
        self.assertNotIn("mqtt",CODE.lower())
        ast.parse(probe)

    def test_route_cache_play_and_anonymous_service_use_same_resolver(self):
        rtc=(COMP/"tuya_rtc_inventory.py").read_text()
        preflight=(COMP/"c9c_cached_video_preflight.py").read_text()
        player=(COMP/"tuya_live_preview.py").read_text()
        init=(COMP/"__init__.py").read_text()
        api=(COMP/"api.py").read_text()
        self.assertIn("camera_cp_device_id=resolve_aosu_cp_device_id(client)[0]",rtc)
        self.assertIn("resolve_cp_id(client)[0]",preflight)
        self.assertIn("resolve_cp_id=resolve_aosu_cp_device_id",player)
        self.assertIn("resolve_cp_id=resolve_aosu_cp_device_id",init)
        self.assertEqual(api.count("self._standalone_c9c_cp_detail=None"),5)
        for source in (rtc,preflight,player,init,api):
            ast.parse(source)


if __name__=="__main__":
    unittest.main()
