# C9C autonome — sélection d'identité Tuya typée (12 novembre 2026)

## État réel du projet avant ce correctif

- Installation de développement : C5L et 2 C9C3CA11 reliées à H1L ;
  vidéo et PTZ confirmés. Conserver leurs chemins et entités.
- C9C autonome : cloud Tuya accepte les deux lectures RTC ;
  `skills.p2pType=4`, `p2pSpecifiedType=4`,
  `CameraInfoBean.id`, `p2pConfig`, `sessionTid`, clé
  locale présents. Le SDP Python AES/KCP peut être construit en RAM.
- La signalisation MQTT précédente a obtenu PUBACK, sans réponse SDP
  confirmée ; cela ne prouve ni destinataire ni transport adéquat.
- Android ADB non-root 1.1 : 672 lignes AOSU inspectées dans une fenêtre
  temporelle valide, sans marqueur P2P. Conclusion non concluante ;
  la piste logcat est clôturée.
- Version installable stable expérimentalement : `0.8.13-beta40`.

## Nouveau constat confirmé dans la vraie APK AOSU 5.10.12

Analyse **hors ligne** des DEX de l'APK fournie par l'utilisateur,
sans publier de code OEM, données d'installation ou secrets :

1. Dans `classes15.dex`, méthode
   `DeviceInfoExtKt.OooO0O0(GzDeviceInfo): String`,
   la décision par type de plateforme utilise une table Kotlin
   `DeviceInfoExtKt$WhenMappings`.
2. Son initialiseur associe explicitement
   `Iot.Gz` au cas 1, `Iot.Mock` au cas 2,
   et **`Iot.Ty` au cas 3**.
3. Les cas Gz/Mock retournent `GzDeviceInfo.deviceId` ;
   la branche Ty lit
   **`GzDeviceInfo.cpDeviceInfo.cpUuid`** et peut
   retourner un identifiant absent/nul si cette fiche manque.
4. Dans `classes16.dex`,
   `TyCameraCenter.Oooo000(String)` recherche d'abord
   un appareil via `IotPlatform.Ty → IotDevice`
   puis appelle `ThingIPCSdk.getCameraInstance()` et
   `IThingIPCCore.createCameraP2P`.
5. Cela distingue deux identifiants longtemps confondus
   dans la recherche :
   - `coopUUID`/ `cpDeviceId` du mapping du service AOSU ;
   - **`cpDeviceInfo.cpUuid`** de la plateforme Tuya.
   Rien ne garantit qu'ils aient la même valeur que le `devId` Tuya.

Ces faits **documentent le choix de l'identifiant dans le SDK** ;
ils ne prouvent pas que l'appel correspondant s'est produit pendant
l'ouverture réelle de la C9C sur le téléphone.

## Correction isolée (branche experiment/c9c-typed-ty-cpuuid)

- Nouveau `extract_c9c_ty_cp_uuid(record)` :
  n'accepte que `cpDeviceInfo.cpUuid` de la fiche AOSU dont le
  numéro de série est déjà associé à l'unique C9C autonome.
  Une autre référence `cpDeviceId`, `coopUUID`, un `deviceId`
  ou un numéro de série ne peut jamais être utilisé comme repli.
- Conservation **temporaire en RAM** ; nettoyage à la fermeture
  et lorsque la topologie ne contient plus une C9C autonome unique.
- Nouveau sélecteur typé pour les **seules commandes actives**
  de C9C autonome :
  - série AOSU ↔ série Tuya ;
  - AOSU `cpDeviceId` ↔ Tuya `cpDeviceId` ;
  - AOSU `cpDeviceInfo.cpUuid` ↔ Tuya `uuid`.
  Les identifiants provenant d'espaces de noms différents ne sont
  plus assimilés à une preuve. Contradictions et doublons bloquent
  la sélection. Un unique candidat reste seulement heuristique :
  **aucune offre vidéo/réveil autorisée**.
- Les lectures sans commande, la C5L et la station H1L ne
  sont pas déplacées vers ce sélecteur.
- Le bouton existant **« Vérifier identité »** compare,
  en lecture seule, la référence `cpUuid` AOSU et le véritable
  UUID retourné par une `Fiche Tuya` récente, à condition que
  la fiche concerne le même `devId`, la même session Tuya
  authentifiée et qu'elle date de moins de 10 minutes.
  Le rapport n'expose que des booléens, jamais leurs valeurs.
- Une égalité des deux UUID n'implique toujours **pas**
  que la vidéo ni la signalisation P2P fonctionnent.
  Le bouton d'identité **n'émet aucune commande**.

## Limite actuelle importante

Si `/v1/dev/getList` ne renvoie pas
`cpDeviceInfo.cpUuid` pour la C9C, cette correction
ne peut **pas** inventer la référence. Dans ce cas, la
correspondance reste non prouvée, et les émissions vidéo
restent bloquées.

La voie à étudier reste le mapping réel AOSU → Tuya
avant `createCameraP2P`, puis la parité de la création
de session Thing-4 avec notre intégration Python.
La simple préparation d'un SDP n'est pas suffisante.

## Validation

Fixtures synthétiques uniquement, aucune caméra, aucun API :
`tests/test_c9c_ty_cp_uuid_identity.py`.
Elles couvrent les bons espaces de noms, les contradictions,
les identifiants erronés, la séparation comptes/sessions,
l'absence de secrets retournés et la préservation C5L/H1L.

**Aucune ressource ou compte appartenant à l'utilisateur n'est
inclus dans le dépôt public.**
