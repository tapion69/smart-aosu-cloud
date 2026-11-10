# AOSU 5.10.12 — traçage du cache AOSU/Tuya

**10 novembre 2026 — recherche statique sur l'APK complet, 17 DEX.**

Archive originale déjà fournie pour les tests : 200 265 946 octets.
SHA-256 : ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7.
L'analyse a été réalisée localement sans accès réseau, aucune caméra, ni compte.
Aucun APK, DEX, code propriétaire ni identifiant privé n'a été mis dans GitHub.

## Neuf constats vérifiés dans le code Android

| Méthode/chemin | Constats statiques |
|---|---|
| classes11.dex — UUIDInfoWebDataItem.OooO0O0 | Lit coopUUID et écrit GzDeviceInfo.cpDeviceId |
| classes15.dex — DeviceBusinessImpl.getDeviceInfo | Délègue à DeviceInfoDataRepo.getDeviceInfo |
| classes15.dex — DeviceInfoRepoImpl.getDeviceInfo | Consulte un cache ConcurrentHashMap |
| classes15.dex — DeviceInfoRepoImpl.OoooOO0 | Charge une liste via DeviceWebService |
| classes15.dex — DeviceInfoRepoImpl$loadDeviceInfoList$1$1.OooO00o | Appelle TyDeviceInfoSource.OooOOO0 |
| classes15.dex — ...$loadDeviceInfoList$1$1$1.OooO00o | Lit GzDeviceInfo.cpDeviceId et appelle TyDeviceInfoSource.OooOOOo |
| classes15.dex — TyDeviceInfoSource.OooO0o | Consulte l'interface d'appareil Tuya IotDevice |
| classes15.dex — TyDeviceInfoSource.OooOOOO | Utilise cpDeviceId comme clé et remplit une ConcurrentHashMap |
| classes15.dex — TyDeviceInfoSource.OooO0oo | Retrouve une entrée par ConcurrentHashMap.get |

Cela étaye une **fusion de la liste AOSU avec la couche Tuya, suivie
d'un rapprochement dans un cache local Android**. Le simple inventaire
AOSU interrogé par Home Assistant n'est pas nécessairement identique
à ce dépôt enrichi construit dans l'application Android.

Le résultat du test beta32 sur la C9C externe a établi :
- aucun des champs coopUUID, cpDeviceId ou cpDeviceInfo.cpDeviceId
  trouvé dans son enregistrement AOSU récupéré par getList ;
- fiche getInfoBySn correcte pour le SN, mais sans référence Tuya ;
- candidat Tuya sélectionné par unicité, toujours non identifié
  formellement comme étant cette caméra ;
- code P2P Thing=4, réponses RTC présentes, mais aucune SDP.

Le code statique ne donne PAS la valeur du CP ID de cette caméra,
ni ne prouve que le cache Android possède cette valeur chez le frère.
Il n'autorise pas à copier un ID au hasard, à associer un productId
ou à supposer que le seul appareil Tuya est la bonne caméra.

## Outil reproductible et protection

L'outil tools/aosu_cp_cache_route_offline.py analyse uniquement des
références de méthodes/champs du SDK dans les DEX 11 et 15. Il affiche
neuf booléens, et toujours :
- runtime_device_identity_confirmed = false ;
- external_c9c_cp_id_recovered = false ;
- network_calls = 0.

Son test synthétique vérifie que ni un productId ni une unicité de
candidat ne deviennent une identité exacte, et ne conserve aucun secret.

## Décision

**Aucune beta33 installable pour le moment.** Conserver la beta32 et
les trois caméras C5L/H1L validées, leurs entités et leurs commandes PTZ.
La prochaine intervention sur l'intégration doit trouver une source de
liaison AOSU/Tuya effectivement accessible et vérifiable pour cette C9C,
avec correspondance exacte. Ne pas répéter les cinq API Tuya ou publier
une nouvelle sonde pour les mêmes champs.

La prochaine enquête technique peut rechercher si des réponses
d'appairage AOSU déjà autorisées exposent la liaison, mais les appels
nécessitant un coopUUID inconnu ne doivent pas être lancés avec des
identifiants inventés.
