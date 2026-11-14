"""Cached AOSU/Tuya C9C identity: refuse known-weak active Play before network.

Synthetic fixtures only. No authentic serials, IDs, credentials, sockets,
camera commands, P2P sessions or media.
"""
from __future__ import annotations
import ast
import json
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
COMP=ROOT/"custom_components"/"smart_aosu_cloud"
GATE=runpy.run_path(str(COMP/"c9c_cached_video_preflight.py"))[
    "cached_c9c_video_preflight"]
SELECT=runpy.run_path(str(COMP/"camera_topology.py"))[
    "select_tuya_standalone_target_typed"]
PREVIEW=(COMP/"tuya_live_preview.py").read_text(encoding="utf-8")
SN="SYNTHETIC_AOSU_SERIAL"
TUYA="SYNTHETIC_TUYA_DEVICE_123"
USER="SYNTHETIC_TUYA_UID"
CP_UUID="SYNTHETIC_TUYA_UUID"


def client(*,cp=None,ty=None,old=False,mismatch=False):
    now=5000
    return SimpleNamespace(
        _standalone_c9c_sn=SN,
        _standalone_c9c_coop_id=cp,
        _standalone_c9c_ty_cp_uuid=ty,
        _sid="SYNTHETIC_AOSU_SID",
        _uid="SYNTHETIC_AOSU_USER",
        _tuya_oem_session=SimpleNamespace(uid=USER,acquired_at=4900),
        _tuya_oem_inventory_cache={
            "created":4000 if old else 4950,
            "session_uid":"OTHER_UID" if mismatch else USER,
            "devices":{TUYA:{"devId":TUYA, "skills":{"p2pType":4}}},
        },
    )


def check(c,now=5000):
    return GATE(c,select_tuya_typed=SELECT,
                resolve_ty_uuid=lambda x:(x._standalone_c9c_ty_cp_uuid,"test"),
                now=now)


class CachedGateTests(unittest.TestCase):
    def test_fresh_single_candidate_is_not_exact_identity(self):
        result=check(client())
        self.assertEqual(result["etat"],"identite_non_prouvee_cache_reutilise")
        self.assertEqual(result["appels_reseau"],0)
        self.assertEqual(result["commandes_camera"],0)
        self.assertEqual(result["offres_mqtt_envoyees"],0)

    def test_exact_cp_to_tuya_dev_id_is_allowed_without_inventing(self):
        self.assertEqual(check(client(cp=TUYA))["etat"],"identite_exacte_cachee")

    def test_exact_aosu_serial_to_tuya_serial_is_allowed(self):
        c=client()
        c._tuya_oem_inventory_cache["devices"][TUYA]["sn"]=SN
        self.assertEqual(check(c)["etat"],"identite_exacte_cachee")

    def test_tuya_cp_uuid_namespace_is_allowed_only_if_exact(self):
        c=client(ty=CP_UUID)
        c._tuya_oem_inventory_cache["devices"][TUYA]["uuid"]=CP_UUID
        self.assertEqual(check(c)["etat"],"identite_exacte_cachee")

    def test_stale_cache_is_inconclusive_not_a_false_denial(self):
        self.assertEqual(check(client(old=True))["etat"],"cache_non_conclusif")

    def test_another_account_session_cache_is_inconclusive(self):
        self.assertEqual(check(client(mismatch=True))["etat"],"cache_non_conclusif")

    def test_expired_auth_session_is_inconclusive(self):
        c=client()
        c._tuya_oem_session.acquired_at=3000
        self.assertEqual(check(c)["etat"],"cache_non_conclusif")

    def test_missing_authenticated_identity_is_inconclusive(self):
        c=client()
        c._sid=None
        self.assertEqual(check(c)["etat"],"cache_non_conclusif")

    def test_invalid_or_empty_inventories_are_inconclusive(self):
        c=client()
        c._tuya_oem_inventory_cache["devices"]={}
        self.assertEqual(check(c)["etat"],"cache_non_conclusif")
        c._tuya_oem_inventory_cache=None
        self.assertEqual(check(c)["etat"],"cache_non_conclusif")

    def test_multiple_ambiguous_tuya_candidates_block_early(self):
        c=client(cp=TUYA)
        c._tuya_oem_inventory_cache["devices"]={
            TUYA:{"devId":TUYA},
            "SECOND_TUYA_DEVICE":{"devId":"SECOND_TUYA_DEVICE",
                                  "cpDeviceId":TUYA},
        }
        self.assertEqual(check(c)["etat"],"identite_non_prouvee_cache_reutilise")

    def test_report_contains_no_identifiers(self):
        for result in (check(client()),check(client(cp=TUYA))):
            raw=json.dumps(result)
            for secret in (SN,TUYA,USER,CP_UUID):
                self.assertNotIn(secret,raw)
            self.assertFalse(result["identifiants_retournes"])
            self.assertFalse(result["secrets_retournes"])


class ControllerWiringTests(unittest.TestCase):
    def _start(self, *, c9c, gate_result):
        tree=ast.parse(PREVIEW)
        c=next(n for n in tree.body if isinstance(n,ast.ClassDef)
               and n.name=="LiveController")
        f=next(n for n in c.body if isinstance(n,ast.FunctionDef)
               and n.name=="start")
        tree=ast.Module(body=[ast.ImportFrom(module="__future__",
            names=[ast.alias(name="annotations")],level=0),f],
            type_ignores=[])
        ast.fix_missing_locations(tree)
        invoked=[]
        def preflight(*args,**kwargs):
            invoked.append("preflight")
            return {"etat":gate_result}
        def readiness(*args):
            invoked.append("readiness")
            return {"pret_cote_limites_locales":False}
        ns={"cached_c9c_video_preflight":preflight,
            "select_tuya_standalone_target_typed":SELECT,
            "resolve_aosu_ty_cp_uuid":lambda x:(None,"none"),
            "resolve_aosu_cp_device_id":lambda x:(None,"aucune"),
            "readiness_live":readiness}
        exec(compile(tree,"<live-controller-start>","exec"),ns)
        class Harness:
            running=False
            preview="OLD_FRAME_SHOULD_NOT_BE_DISPLAYED"
            _last_result={}
            _status="pret"
            _retry=SimpleNamespace(remaining=lambda:0)
            def _notify(self):pass
            def _deny_start(self,status,**kwargs):
                return {"etat":status,**kwargs}
        h=Harness()
        h.client=client()
        h.start=ns["start"].__get__(h,Harness)
        result=h.start(password_confirmed=True,candidate_confirmed=True,
                       standalone_c9c_video_test=c9c)
        return result,invoked,h

    def test_c9c_known_weak_identity_blocks_before_readiness_and_network(self):
        result,events,h=self._start(
            c9c=True,gate_result="identite_non_prouvee_cache_reutilise")
        self.assertEqual(events,["preflight"])
        self.assertEqual(result["etat"],"c9c_identite_non_prouvee_cache_frais")
        self.assertFalse(result["nouvelle_offre_mqtt"])
        self.assertEqual(result["appels_reseau"],0)
        self.assertIsNone(h.preview)

    def test_historic_cameras_do_not_use_c9c_gate(self):
        result,events,h=self._start(
            c9c=False,gate_result="identite_non_prouvee_cache_reutilise")
        self.assertEqual(events,["readiness"])
        self.assertEqual(result["etat"],"demarrage_non_lance_limitation")

    def test_exact_cached_identity_proceeds_to_existing_readiness(self):
        result,events,h=self._start(
            c9c=True,gate_result="identite_exacte_cachee")
        self.assertEqual(events,["preflight","readiness"])
        self.assertEqual(result["etat"],"demarrage_non_lance_limitation")


if __name__=="__main__":
    unittest.main()
