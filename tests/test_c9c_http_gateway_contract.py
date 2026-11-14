"""Native-style HTTP offer gateway contract with mocked network only.

The real Tuya signer, AOSU APK, accounts, and remote camera are never loaded.
"""
from __future__ import annotations
import ast
from pathlib import Path
import unittest

SRC=(Path(__file__).resolve().parents[1]/"custom_components"/
     "smart_aosu_cloud"/"tuya_uid_gateway.py")
TREE=ast.parse(SRC.read_text(encoding="utf-8"))
NODES=[n for n in TREE.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))
       and n.name=="do_oem_thing4_session_offer_once"]
assert len(NODES)==1

class FakeSession:
    sid="synthetic_sid"
    uid="synthetic_uid"
    ecode="synthetic_ecode"

class FakeError(Exception):
    pass

def gateway_with_calls():
    history=[]
    def mock_call(identity,signer,mode,**kwargs):
        history.append(kwargs)
        return {}, {}, {'acceptation_explicite':True,
                        'rejet_explicite':False}
    tree=ast.Module(body=[
        ast.ImportFrom(module="__future__",
                       names=[ast.alias(name="annotations")],level=0),
        NODES[0]],type_ignores=[])
    ast.fix_missing_locations(tree)
    ns={"TuyaAuthSession":FakeSession,"OEMGatewayError":FakeError,
        "_ENDPOINT":"https://unit.test.invalid",
        "_call_api":mock_call}
    exec(compile(tree,str(SRC),"exec"),ns)
    return ns["do_oem_thing4_session_offer_once"],history

def payload(target):
    return {"header":{"to":target,"type":"offer","sessionid":"session_001"},
            "msg":{"sdp":"synthetic_SDP"}}

class HttpGatewayContractTests(unittest.TestCase):
    target="tuyaCamSynthetic001"
    args={
        "ttid":"sdk_international@test","device_id":"synthetic_install",
        "endpoint":"https://unit.test.invalid"
    }

    def test_absent_manual_consent_prevents_any_network(self):
        gateway, history=gateway_with_calls()
        with self.assertRaises(FakeError):
            gateway(object(),object(),"sha256_material",FakeSession(),
                    target=self.target,form_data=payload(self.target),
                    explicit_consent=False,**self.args)
        self.assertEqual(history,[])

    def test_wrong_target_never_reaches_gateway(self):
        gateway, history=gateway_with_calls()
        with self.assertRaises(FakeError):
            gateway(object(),object(),"sha256_material",FakeSession(),
                    target=self.target,form_data=payload("other_camera"),
                    explicit_consent=True,**self.args)
        self.assertEqual(history,[])

    def test_one_http_call_with_java_native_action_and_version(self):
        gateway, history=gateway_with_calls()
        result=gateway(object(),object(),"sha256_material",FakeSession(),
                       target=self.target,form_data=payload(self.target),
                       explicit_consent=True,**self.args)
        self.assertEqual(len(history),1)
        self.assertEqual(history[0]["action"],"thing.m.rtc.session.offer")
        self.assertEqual(history[0]["api_version"],"1.0")
        self.assertEqual(history[0]["form_data"],payload(self.target))
        self.assertNotIn("thing.m.rtc.session.offer_1.0",str(history))
        self.assertEqual(result,{"http_ok":True,
                                 "serveur_accepte":True,
                                 "rejet_explicite":False})

    def test_refusal_is_classified_without_leaking_raw_error(self):
        gateway,history=gateway_with_calls()
        # Underlying API stub returns a refusal and a private server message.
        def rejected_api(identity,signer,mode,**kwargs):
            history.append(kwargs)
            return {"success":False,"errorMsg":"PRIVATE_NOT_FOR_LOG"}, {}, {
                "acceptation_explicite":False,
                "rejet_explicite":True}
        original=gateway.__globals__["_call_api"]
        original_classifier=gateway.__globals__.get("_safe_server_refusal")
        try:
            gateway.__globals__["_call_api"]=rejected_api
            gateway.__globals__["_safe_server_refusal"] = lambda *_args: {
                "categorie_refus":"parametres",
                "type_code_erreur":"symbolique",
                "code_erreur_present":True}
            result=gateway(object(),object(),"sha256_material",FakeSession(),
                target=self.target,form_data=payload(self.target),
                explicit_consent=True,**self.args)
        finally:
            gateway.__globals__["_call_api"]=original
            if original_classifier is None:
                gateway.__globals__.pop("_safe_server_refusal",None)
            else:
                gateway.__globals__["_safe_server_refusal"]=original_classifier
        self.assertEqual(len(history),1)
        self.assertEqual(result["categorie_refus"],"parametres")
        self.assertEqual(result["type_code_erreur"],"symbolique")
        self.assertNotIn("PRIVATE",str(result))

    def test_gateway_does_not_forward_raw_server_data(self):
        gateway, history=gateway_with_calls()
        actual=gateway(object(),object(),"sha256_material",FakeSession(),
                       target=self.target,form_data=payload(self.target),
                       explicit_consent=True,**self.args)
        self.assertNotIn("synthetic_sid",str(actual))
        self.assertNotIn(self.target,str(actual))
        self.assertNotIn("synthetic_SDP",str(actual))

if __name__=="__main__":
    unittest.main()
