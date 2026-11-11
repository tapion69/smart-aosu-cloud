# C9C autonome — résultat beta36 et parcours P2P natif Android
Date : 11 novembre 2026

## Retour matériel beta36 — acquis, pas de nouvelle tentative d'UUID

La caméra C9C autonome sans H1L a renvoyé :
- fiche Tuya : `skills` présent, `p2pType` Thing = **4**,
  `productBean` absent, catégorie/modèle/SN Tuya absents ;
- fiche AOSU : numéro de série exact, sans identifiant `deviceId`
  AOSU ni référence Tuya démontrés ;
- recherche inverse AOSU avec le **seul `uuid` Tuya réellement
  renvoyé par la fiche**, après les variations des beta34/35 :
  une entrée, `coopUUID` présent et égal au paramètre demandé,
  `devType` présent, **`deviceId` absent**.
- état affiché : `coop_uuid_retourne_sans_device_id`,
  `reference_cp_resolue=false`,
  `liaison_exacte_confirmee=false`.

**Interprétation sûre :** la requête est reconnue au niveau de la forme,
mais une entrée incomplète peut être un simple écho de paramètre.
On ne sait toujours pas que le `devId` Tuya identifié par unicité
est bien la caméra AOSU. Inutile de retenter d'autres variantes de
`getListByCoopUUIDList` avec les mêmes données.

## Audit réel hors ligne sur l'APK complète (17 DEX)

La méthode `ThingSmartCameraP2PSync.innerConnect` de
`classes6.dex` fait **17 vérifications de références** recoupées
avec `processCameraInfo`, `requestCameraConfig`,
`CameraConstant.getDeviceP2PType` et
`TyCameraCenter.Oooo000` dans `classes16.dex` :

1. `ThingIPCSdk.getHomeProxy` ;
2. `IThingIPCDevice.getDeviceBean` (instance de la plateforme) ;
3. `DeviceBean.getSkills` ;
4. `CameraConstant.getDeviceP2PType` ;
5. `Map.get` depuis les paramètres des capacités ;
6. `requestCameraConfig` ;
7. `CameraBusiness.requestCameraInfo` ;
8. `CameraInfoBean.getP2pPolicy` ;
9. `CameraInfoBean.getSessionTid` ;
10. `getClientTid` ;
11. `CameraInfoBean.getP2PConfigStr` ;
12. `CameraInfoBean.getP2pId` ;
13. `DeviceBean.getLocalKey` ;
14. `ConfigCameraBean.setSkill` ;
15. `ConfigCameraBean.setClientTraceId` ;
16. `createDeviceIPC` ;
17. `IThingIPCCore.createCameraP2P` via `TyCameraCenter`.

L'ordre exact des opérations réseau, les valeurs de ces champs,
les messages natifs et la compatibilité sur la C9C **ne sont
pas démontrés** par ces références DEX. L'analyse ne lance aucun
SDK Android. Aucune clé ou identité n'est publiée.

L'implémentation Home Assistant Python reconstruit une
offre SDP AES/KCP depuis les retours API dans
`tuya_media_bootstrap.py`, puis la publie via
`tuya_mqtt_offer.py`. Elle n'exécute **pas**
`IThingIPCCore.createCameraP2P`, ne possède pas de
`ThingIPCSdk.getHomeProxy` et n'a pas de parité de
trames native démontrée. Un PUBACK MQTT ou un RTC accepté
n'équivalent donc pas à une session P2P ouverte.

## Vérification reproductible sans réseau

Outil source public indépendant du binaire fournisseur :

```bash
python tools/aosu_c9c_native_p2p_route_offline.py /chemin/prive/Aosu_5.10.12_21839.apks.apk
```

L'audit affiche uniquement 17 booléens, un total et
`binary_protocol_parity_proven=false`,
`device_identity_proven=false`,
`ready_for_camera_send=false`.
**Sur l'APK complète analysée localement, les 17 références
ont bien été retrouvées.** Les tests CI vérifient l'absence
de conclusion positive artificielle avec des entrées synthétiques.

## Prochaine expérience vraiment utile

Ne pas relancer les sondes CP, `Fiche Tuya` ou les offres
MQTT actuelles : elles ne révèlent pas pourquoi
`ThingSmartCameraP2PSync` ne reçoit pas de réponse.

La priorité est un **précontrôle des prérequis du chemin natif**
pour la seule C9C du compte :
- identifier si le `DeviceBean` Tuya est suffisamment complet
  (`devId`, `skills.p2pType=4`, `localKey`,
  catégorie, P2P config, politique de transport) ;
- obtenir, depuis les réponses de lecture déjà autorisées,
  l'existence des champs `sessionTid`, `p2pPolicy`,
  `clientTid` sans jamais exposer leur valeur ;
- seulement si la plateforme et la cible sont vérifiées,
  envisager un unique essai P2P basé sur le bon type et le bon
  ordre de création de session.

Un contrôle de champs n'est pas une preuve de fonctionnement et
n'autorise aucune commande caméra. Conserver la version installée
`0.8.13-beta36` pendant cet audit.

## Références externes officielles

- Tuya, Android Camera Device :
  https://tuyainc.github.io/tuyasmart_camera_android_sdk_doc/en/resource/home_device.html
- Tuya, caméra : `getP2PType(devId)` et
  `createCameraP2P(devId)` :
  https://developer.tuya.com/en/docs/app-development/homedevice?id=Kceuhbr6hms0u
- Tuya, distinction `uuid` vs `deviceId` :
  https://support.tuya.com/en/help/_detail/K9g77zed10l6r

Les vidéos/PTZ des trois caméras déjà opérationnelles
(1 C5L + 2 C9C3CA11/H1L) restent inchangés.
