# C9C autonome — beta37 : précontrôle du vrai parcours Thing P2P

Date : 11 novembre 2026. Version exploratoire **en lecture seule**.

## Ce qu'a démontré la beta36

AOSU accepte un UUID Tuya en entrée de l'API inverse et
renvoie `coopUUID` identique, mais **aucun `deviceId`**.
Le code affichait `coop_uuid_retourne_sans_device_id`,
`reference_cp_resolue=false` et
`liaison_exacte_confirmee=false`.

Ce n'est pas une preuve d'identité ni un lien vidéo.
Ne plus répéter les variantes de l'API
`getListByCoopUUIDList` sans élément nouveau.

## Audit hors ligne de la vraie APK

La méthode Android native `ThingSmartCameraP2PSync.innerConnect`
charge notamment le `DeviceBean`, la carte des `skills`,
le type P2P, `CameraInfoBean`, sa politique P2P et ses
références de session. `processCameraInfo` utilise le
`localKey`, `p2pId`, `p2pConfigStr`, des champs de
configuration et un `clientTid`, puis crée l'objet IPC.

Le code public `tools/aosu_c9c_native_p2p_route_offline.py`
confirme **17/17 références statiques** sur la vraie APK 5.10.12,
sans l'exécuter ni y accéder en réseau. Les références DEX
**ne prouvent aucune parité native avec le code Python**.

## Nouveau bouton « Préparation SDK »

À la place de demandes répétées d'identification CP,
la carte C9C autonome propose désormais **Préparation SDK**.

Une activation manuelle explicite :
1. utilise le compte Tuya déjà configuré (ou son login autorisé) ;
2. lit **une seule fiche Tuya** via `thing.m.device.get` ;
3. lit **une seule configuration IPC-v4** via
   `m.ipc.v4.rtc.config.get` ;
4. examine les résultats en mémoire uniquement, sans exposer
   identifiants, IP, URL, clés, mot de passe, jetons ni valeurs SDP.

Le rapport affiche les booléens de présence de :
- concordance de l'identifiant Tuya dans sa propre fiche ;
- `skills.p2pType=4`, `localKey`, `productBean` et catégorie `sp` ;
- `p2pConfig`, `p2pPolicy`, `sessionTid`,
  `p2pId`, `sessionId`, `clientTid` dans les réponses de
  **ces API**.

**Attention :** une absence dans ces réponses cloud
ne prouve pas l'absence de la donnée dans le
`DeviceBean`/SDK Android officiel. Cette sonde
ne peut pas créer un objet natif `ThingIPCSdk`
depuis un processus Python Home Assistant.

Le mode est borné à deux lectures métier. Les recherches
de groupes éventuelles et le login Tuya restent soumis
aux limitations existantes. Le diagnostic est limité à
une fois toutes les cinq minutes.

Aucune offre MQTT, SDP, vidéo, réveil, PTZ ou commande de
caméra n'est effectuée. C5L et C9C3CA11/H1L ne sont pas touchés.

## Test physique de l'utilisateur

1. Installer la version `0.8.13-beta37` depuis `main`,
   redémarrer Home Assistant, puis Ctrl+F5 dans le navigateur.
2. Sur la **C9C autonome uniquement**, cliquer
   **Préparation SDK** **une seule fois**.
   Il n'est pas nécessaire de cliquer auparavant sur
   `Fiche Tuya` ou `Fiche AOSU`.
3. Envoyer le **texte anonymisé affiché**, notamment :
   - clé locale disponible ;
   - `skills Thing 4` ;
   - `productBean` et catégorie `sp` ;
   - `configuration P2P`, `p2pPolicy`,
     `sessionTid`, `p2pId`, `sessionId`.
4. Si la sonde retourne une limite d'inventaire/login,
   ne pas répéter les actions avant l'expiration du délai.

## Critères pour la prochaine expérience vidéo

Le diagnostic peut expliquer si l'application Python manque
des prérequis nécessaires à la création de session P2P.
Il ne peut pas prouver qu'une caméra sera compatible à lui seul.
Avant une nouvelle offre physique, établir une correspondance
de cible fiable et un chemin de session conforme, plutôt
que d'envoyer des essais 302 à l'aveugle.

Les 17 références DEX ont été inspectées localement avec l'APK
fournie par l'utilisateur. Seuls des tests synthétiques
sans caméra ni données privées sont exécutés sur GitHub.
