# Smart AOSU — clôture des sources cloud CP et étude du pont natif Tuya
**13 novembre 2026 — recherche hors ligne, pas de mise à jour Home Assistant**

## Retour utilisateur sur 0.8.13-beta43

Les trois captures sont cohérentes, avec la carte et le service tous les deux
en b43 :

- **Fiche AOSU : obtenue**, `cp_uuid_absent_du_detail`.
- L'ancienne recherche inverse CP n'est plus lancée.
- La fiche Tuya contient un UUID, `skills.p2pType=4`, mais ni SN AOSU ni
  référence AOSU pertinente.
- `cpUuid Ty AOSU présent = non`,
  `UUID Tuya récent = oui`,
  `cpUuid AOSU = UUID Tuya = non`.
- `ptz_iot_platform = Ty`, mais le fournisseur P2P déclaré dans
  l'inventaire AOSU est `INDETERMINE`.
- Cible Tuya proposée seulement par l'heuristique
  `appareil_tuya_unique_sans_categorie_video`,
  **pas par une identité confirmée**.
- Aucun essai vidéo ou PTZ exécuté par le diagnostic.

`getList`, `getInfoBySn` et `getListByCoopUUIDList` ont déjà été
explorés. **Ne pas refaire les mêmes requêtes ou renouveler les variantes
de sonde UUID/CP**. Une donnée présente dans l'objet Android enrichi
n'est pas forcément exposée par les API AOSU HTTP.

## Preuve supplémentaire tirée du vrai APK AOSU 5.10.12

L'outil public `tools/aosu_ty_device_enrichment_offline.py`
analyse uniquement les DEX de l'APK personnelle en local, sans publier
le binaire, les IDs, clés, journaux, chaînes du serveur ou code OEM.
Sur l'APK propriétaire fournie par l'utilisateur, une vérification
locale a trouvé les **14 marqueurs statiques attendus sur 14**.

### Chemin de données

1. `DeviceInfoRepoImpl` obtient les listes d'appareils AOSU puis
   invoque `TyDeviceInfoSource`. Le flux n'est pas seulement un JSON
   `/v1/dev/getList` directement passé aux caméras.
2. `TyDeviceInfoSource` appelle
   `IotPlatform.Ty.getDevice()`, puis l'interface `IotDevice` :
   - `Oooo00O(Callback)` pour une liste Tuya asynchrone ;
   - `Oooo0OO()` pour lire la liste du cache SDK ;
   - `OoooO00(Set, Callback, Callback4)` pour la récupération
     associée à des références de périphériques.
3. Le cache du pont est alimenté sous les clés
   `GzDeviceInfo.cpDeviceId` ; une lecture
   `ConcurrentHashMap.get` permet de réutiliser ce lien.
4. Un événement `PlatformDeviceInfo` contient
   `cpDeviceId`. Le chemin d'enrichissement utilise
   `DeviceBusiness.getDeviceInfo`, puis
   `GzDeviceInfo.setCpDataInfo`.
5. Pour la branche plateforme `Iot.Ty`,
   `DeviceInfoExtKt.OooO0O0` lit **`GzDeviceInfo.cpDeviceInfo.cpUuid`**
   dans cet objet enrichi.
6. `TyDeviceCenter` lit `GzDeviceInfo.cpDeviceId`.
   `TyCameraCenter.Oooo000(String)` récupère d'abord
   un identifiant au moyen de **`IotDevice.Oooo000(String)`**,
   puis appelle `ThingIPCSdk.getCameraInstance()` et
   `IThingIPCCore.createCameraP2P(String)`.

### Détail notable : l'identifiant est transformé avant la création P2P

L'inspection du flux de registres DEX `classes16.dex` sur
`TyCameraCenter.Oooo000` confirme :
- invocation `IotDevice.Oooo000` à l'unité 10,
  puis `move-result-object v0` à l'unité 13 ;
- `ThingIPCSdk.getCameraInstance` à l'unité 48,
  puis `move-result-object v5` à l'unité 51 ;
- `createCameraP2P` à l'unité 54,
  avec `v5` (instance SDK) et **`v0`** (résultat de la
  conversion d'identifiant).

Cette lecture décrit un **chemin Android statique**, pas une preuve
qu'il a été exécuté pour la C9C précise. L'entrée et la sortie exactes
de `IotDevice.Oooo000` ne sont pas connues. Il n'est **pas** correct
d'affirmer que la sortie diffère du `devId` Tuya disponible :
cela reste à vérifier.

## Conséquences pour notre intégration Home Assistant

La bêta40 a confirmé :
- réponses RTC classiques et IPC-v4 disponibles ;
- `p2pSpecifiedType=4` / `Thing` ;
- `CameraInfoBean.id = devId Tuya sélectionné` ;
- SDP AES/KCP préparé en RAM pour les deux API.

Cela valide la **structure de préparation** et la cohérence interne
Tuya. Cela **ne** valide ni le pont AOSU→Tuya, ni la parité de
`ThingIPCSdk`, ni l'acceptation de la signalisation par la caméra.
Un PUBACK MQTT ne constitue pas un SDP answer.

### Blocage concret

Dans l'application Android, la relation des appareils est composée
au niveau du **SDK client et de son cache d'appareils**, avec une
jointure portant sur `cpDeviceId`.
Notre client AOSU Python ne reçoit pas cette relation dans les
réponses HTTP actuellement accessibles. Le fait qu'un seul appareil
figure au compte Tuya ne suffit pas à établir une correspondance.

Ne pas inventer `cpUuid`, ne pas assimiler `AOSU.deviceId`,
`AOSU.sn`, `AOSU.coopUUID`, `Tuya.uuid` et `Tuya.devId`.
Ne pas déverrouiller la commande vidéo autonome sur une heuristique.

### Prochain chantier qui mérite du code, sans multiplier les diagnostics

1. Comparer la sémantique de `IotDevice.Oooo000`
   aux **champs exposés par les API Tuya légitimes**, à l'aide de
   fixtures strictement anonymisées et de l'APK statique uniquement.
   Confirmer si sa sortie est déjà le `devId` de l'inventaire.
2. Décider si le pont peut être réalisé **sans SDK Android** :
   liaison d'identité autorisée, puis signalisation Thing-4
   équivalente, avec preuves indépendantes.
3. Si aucun champ d'association AOSU↔Tuya n'est fourni
   par les SDK/API publics, documenter cette limitation
   au lieu de créer artificiellement une correspondance.
4. Un essai physique futur n'aura de valeur qu'après
   un vrai correctif du chemin de connexion et une
   preuve de cible ; une lecture statique ou un nouveau
   bouton de présence de champ ne constitue pas ce correctif.

## État de publication

- **Aucune bêta44 Home Assistant** issue de cette analyse.
- **Bêta43 conservée** comme dernière version installable.
- Nouvel audit reproductible et tests synthétiques uniquement
  dans la branche de recherche, puis dans `main` si CI réussie.
- Vidéo et PTZ déjà validées pour la C5L et les 2 C9C3CA11/H1L :
  **chemin de production intact**.
- Ni APK OEM ni secrets/identifiants de l'installation dans GitHub.
