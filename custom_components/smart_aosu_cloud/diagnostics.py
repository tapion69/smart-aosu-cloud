"""Safe diagnostics: no account, device ID, SID, IP, URL or secret."""
from .const import VERSION
async def async_get_config_entry_diagnostics(hass,entry):
    co=entry.runtime_data
    data=co.data or {}
    counts={"appareils":len(data),"avec_energie_brute":0,"avec_wifi_brut":0,"avec_base":0}
    for r in data.values():
        counts["avec_energie_brute"]+=r.get("electricity") is not None
        counts["avec_wifi_brut"]+=r.get("wifi_signal") is not None
        counts["avec_base"]+=bool(r.get("via_device"))
    import copy
    provider=getattr(co.client,"_provider_snapshot",None)
    return {"version":VERSION,"cloud_lecture_seule":True,"derniere_lecture_reussie":co.last_update_success,**counts,
            "audit_provider_p2p":copy.deepcopy(provider) if provider is not None else {"resultat":"inventaire_non_recu"}}
