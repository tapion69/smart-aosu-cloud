# C9C autonome — source réelle du pont d'identité Android et arrêt des offres HTTP isolées

**14 novembre 2026 — résultat de l'analyse statique de l'APK AOSU 5.10.12 du propriétaire**.
Le binaire OEM et les données de comptes/caméras ne sont **pas** versés au dépôt.

## 1. Ce qui construit le lien manquant dans AOSU Android

Les DEX 15 et 16 de l'APK propriétaire ont été étudiés localement,
avec des références de méthodes *propres à cette version*.
Le SHA-256 de `classes15.dex` est
`f61eac81615dab99ea5fae75becdb3309d6c8010cba44bfb78517b405673e426`.

La mise en correspondance n'est **pas** un simple champ `getInfoBySn` :

1. `DeviceInfoRepoImpl.Ooooo0o(Map)` (#2455) transfère le cache de fiches AOSU vers `TyDeviceInfoSource.OooOOOO(Map)` (#2501).
2. `TyDeviceInfoSource.OooOOOO` parcourt les entrées de la table, lit `GzDeviceInfo.cpDeviceId` depuis les valeurs, puis met à jour une `ConcurrentHashMap` via `clear`/`putAll`. La trace de log OEM appelle cette table `deviceIdTy2GzMap`.
3. `TyDeviceInfoSource.OooO0oo(String)` (#2495) est une **lecture** de cette `ConcurrentHashMap` ; ce n'est **pas** une API HTTP.
4. L'observateur `TyDeviceInfoSource$init$1.OooO00o(PlatformDeviceInfo)` (#2474) lit `PlatformDeviceInfo.cpDeviceId`, effectue la recherche `OooO0oo`, récupère une fiche AOSU par `DeviceBusiness.getDeviceInfo`, puis enrichit cet objet via **`GzDeviceInfo.setCpDataInfo(PlatformDeviceInfo)`**.
5. `TyDeviceInfoSource` obtient par ailleurs ses données Tuya en appelant des méthodes d'`IotPlatform.Ty.getDevice()` : liste asynchrone `IotDevice.Oooo00O`, cache SDK `Oooo0OO` et récupération groupée `OoooO00` sur une sélection. Ces méthodes sont **des interfaces du SDK Android connecté**, et non des réponses HTTP `/v1/dev/getList` exposées à HA.
6. Le pont caméra `TyDeviceCenter.Oooo000` (DEX16 #10091) lit la fiche `GzDeviceInfo.cpDeviceId` ; `TyCameraCenter.Oooo000` (#9177) passe ce résultat sans transformation visible à `ThingIPCSdk.createCameraP2P(String)`.

Cette séquence explique comment **l'application officielle peut connaître un lien que Home Assistant ne voit pas**. Aucune de ces constatations statiques ne révèle la valeur `cpDeviceId` réelle de la caméra du frère.

## 2. Limite concrète du client Python actuel

`api.py.refresh` lit la réponse authentifiée AOSU et utilise
`extract_c9c_cp_reference` pour copier en RAM un `cpDeviceId` ou
`coopUUID` **uniquement s'il est effectivement présent dans la fiche C9C liée au SN**.
Le contrôle de la bêta43 avait déjà montré que ce lien était absent dans les
réponses HTTP du compte de test. La comparaison du SN de l'application officielle
avec le cache AOSU de HA en bêta44-rc2 était **exacte**, mais c'est une preuve
**AOSU↔AOSU**, pas un pont **AOSU↔Tuya**.

La méthode `IotDevice.Oooo0OO` dépend du SDK authentifié Android. Un programme
HA Linux Python ne peut pas simplement appeler ce SDK en important les bibliothèques
Android ARM64. Le code Java natif analysé ne présente pas d'endpoint réseau
portable équivalent démontré à ce stade.

**Conclusion :** avec les réponses cloud HTTP effectivement obtenues, la
jointure exacte de cette caméra reste **indisponible** ; changer une comparaison
de chaînes sans fournir la référence ne suffira pas.

## 3. Code et protection ajoutés dans la PR expérimentale

- `camera_topology.py` reconnaît un rapprochement exact
  `AOSU.cpDeviceId == Tuya.devId` **seulement si les deux sources sont
  indépendantes, non ambiguës et présentes**. La simple unicité du candidat
  n'est pas une identité et ne passe pas la garde de la vidéo.
- `c9c_identity_diagnostic.py` ne retourne qu'une étiquette fixe, jamais
  un `devId`, un SN ou une clé.
- Après **deux refus explicites** de `thing.m.rtc.session.offer` chez le frère,
  le test manuel HTTP expérimental est **suspendu sur la branche** :
  `offre_http_suspendue_parite_session_absente`,
  `requete_http_effectuee=false`, `appel_reseau=0`.
  Ce blocage intervient **avant toute découverte, authentification ou publication**
  et n'affecte pas les parcours vidéo/PTZ C5L et C9C-H1L.
- Cette suspension reste une modification **en PR draft**, non installée
  dans `main` et pas encore déployée sur le Home Assistant du frère.
  Il ne faut **pas** interpréter cela comme une mise à jour déjà reçue.

## 4. Seule suite de développement réellement justifiée

Deux problèmes **indépendants** restent à résoudre avant un nouvel essai vidéo :

- **Identité :** obtenir le mapping de façon autorisée depuis un service/SDK
  où il est réellement disponible ; une éventuelle solution Android doit
  respecter l'isolement des données de l'application AOSU et ses autorisations,
  sans prétendre lire son stockage privé depuis une autre application sans root.
- **Session Thing-4 :** construire un client portable équivalent à
  `createDevice → setCameraConfig → connect`, comprenant les capacités,
  callbacks d'état, génération SDP native et jetons. Les deux offres
  HTTP isolées ont été rejetées ; changer `header`, `bizDM`, `session.init`
  ou `udp_token` au hasard n'est pas une prochaine étape recevable.

**Aucune troisième tentative HTTP, aucun réveil ou PTZ n'est demandé.**
Le projet `main` doit rester sur `0.8.13-beta44-rc3` avec ses caméras
historiques inchangées. La PR draft n'est pas une nouvelle bêta vidéo.

## Références

- Code concerné : `camera_topology.py`, `c9c_identity_diagnostic.py`,
  `tuya_rtc_inventory.py` et `api.py`.
- Outil précédent `tools/aosu_ty_device_enrichment_offline.py`
  contrôlait déjà les 14 marqueurs globaux de cette chaîne dans le binaire
  réel. Le présent travail précise les **appels et rôles de la map interne** ;
  il ne prétend pas avoir capturé son contenu pour la C9C du frère.
- `docs/C9C_TY_DEVICE_CPDEVICEID_TO_DEVID_2026-11-14.md`.
