# C9C autonome — lien Android exact `cpDeviceId` AOSU → `devId` Tuya

**14 novembre 2026 — code limité au sélecteur C9C, branche expérimentale, aucun test vidéo.**

## Découverte sur la véritable APK AOSU 5.10.12

Les DEX originaux fournis par le propriétaire ont été inspectés en local, sans
publication des binaires, clés ou identifiants. Archive APKS SHA-256 :
`ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7`.
`classes16.dex` SHA-256 :
`f4a346265e40aa33a198c61b6b78e7d420ce65ae9cb036c4db7734355472a84c`.

La méthode **`TyDeviceCenter.Oooo000(String)`** (#10091, DEX) :
- appelle `DeviceBusiness.getDeviceInfo(String)` (#1533) ;
- si un `GzDeviceInfo` est trouvé, lit son champ **`cpDeviceId`** ;
- renvoie cette valeur **directement**, sans conversion ni interpolation ;
- si la fiche est absente, renvoie `null`.

La méthode **`TyCameraCenter.Oooo000(String)`** (#9177) :
- appelle l'interface `IotDevice.Oooo000(String)` (#1472), dont l'implémentation Tuya est ci-dessus ;
- stocke son résultat en registre `v0` ;
- transmet ce même `v0` à `IThingIPCCore.createCameraP2P(String)` (#44022).

La documentation officielle Tuya décrit **`createCameraP2P(String devId)`** et précise
que ce paramètre est **l'identifiant de l'appareil** :
https://developer.tuya.com/en/docs/app-development/livestream?id=Ka6nuvynnjk7h .
Cela donne un fondement direct au rapprochement
**AOSU `GzDeviceInfo.cpDeviceId` ↔ Tuya `DeviceBean.devId`**,
qui manquait à notre sélecteur typé. Ce lien n'autorise pas de comparer
`AOSU.cpUuid` à `Tuya.devId` ou `SN AOSU` à un autre identifiant au hasard.

## Correctif, sans inférence hasardeuse

Le sélecteur actif `select_tuya_standalone_target_typed`, limité à la C9C autonome :
- reconnaît désormais **seulement** la valeur `cpDeviceId` déjà extraite d'une fiche AOSU de la caméra identifiée par son SN, lorsqu'elle est **exactement égale à la clé `devId` du véritable appareil Tuya** ;
- vérifie que le `DeviceBean.devId` dans l'enregistrement correspond à la clé d'inventaire ;
- refuse toute contradiction de série, d'UUID ou de `cpDeviceId` au sein du même objet, toute correspondance multiple et toute cible ambiguë ;
- ne considère **jamais** un `cpUuid` égal à `devId` comme une preuve ;
- ne confond pas appareil unique et identité prouvée ;
- conserve sans modification les chemins C5L et C9C/H1L.

L'étiquette fixe est `identite_exacte_cp_device_id_dev_id`. Le service
`diagnostiquer_identite_c9c_autonome` peut la retourner en lecture seule,
sans aucun SN, ID, jeton ou secret. Le fonctionnement vidéo **n'est pas prouvé**
par cette égalité ; les contrats SDP/états natifs restent à reproduire.

## Limite importante de la C9C du frère

Les tests précédents bêta42 et bêta43 indiquaient :
`cpUuid Ty AOSU présent : non`, `coopUUID AOSU : absent`,
`UUID Tuya : présent`, et la cible
`appareil_tuya_unique_sans_categorie_video`.

**Ce correctif n'invente pas le `cpDeviceId` absent** de ces réponses HTTP.
Il ne déverrouillera donc pas le direct de cette installation sans une référence
exacte réellement disponible. Le SN de l'application AOSU correspond au SN
mémorisé dans Home Assistant, mais cette égalité reste interne à AOSU.

L'application officielle Android dispose d'un cache `GzDeviceInfo` enrichi
par `TyDeviceInfoSource`, tandis que notre intégration n'en reçoit pas encore
la jointure `cpDeviceId` dans l'API cloud du compte. La priorité pour
**cette caméra** reste d'accéder légitimement à une preuve d'identité équivalente,
puis de reproduire l'initialisation et la négociation de session du SDK.

## Validation et déploiement

CI de la branche :
https://github.com/tapion69/smart-aosu-cloud/actions/runs/43589912612

Les tests synthétiques couvrent correspondance exacte, deux appareils,
faux UUID, contradictions explicites, référence AOSU absente,
résultat HA anonymisé et non-régression de la topologie C5L/H1L.

**Aucune commande de caméra ni requête réseau n'a été émise par ce chantier.**
Ne pas promouvoir ce changement en nouvelle bêta **vidéo** tant que la C9C du
frère ne dispose pas de la référence typée et que la parité de session
`createDevice → setCameraConfig → connect` n'est pas établie.
