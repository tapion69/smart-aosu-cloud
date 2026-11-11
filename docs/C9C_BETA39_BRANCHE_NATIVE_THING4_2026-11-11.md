# Smart AOSU — bêta39 : branche Thing-4 du SDK P2P

Date : 11 novembre 2026. Cette sonde concerne **uniquement la C9C autonome**, sans H1L.

## Résultat réel de la bêta38

La C9C autonome présente :
- Fiche Tuya acceptée, même identifiant Tuya, `skills.p2pType=4`,
  clé locale disponible.
- Deux API acceptées : `m.ipc.v4.rtc.config.get` et
  `thing.m.rtc.config.get`.
- Les deux retournent un objet `p2pConfig`, `sessionTid`,
  `p2pPolicy`, `sessionId`.
- Aucune ne retourne `p2pId` à l'emplacement examiné.
- RTC classique : `p2pSpecifiedType`, mot de passe et `skill`
  présents ; `token` absent.
- Aucun lien AOSU/Tuya formel, aucune offre acceptée, aucune vidéo.

## Découverte : le SDK Android ne lit pas le même champ pour les types 2 et 4

Examen **hors ligne** du vrai `classes6.dex` d'AOSU 5.10.12
(fichier personnel, non publié). Les références de méthodes et les
branchements conditionnels de
`ThingSmartCameraP2PSync.processCameraInfo` montrent :

- Fournisseur **TUTK** : une première branche utilise
  `CameraInfoBean.getP2pId` et émet un diagnostic si celui-ci manque.
- `CameraInfoBean.getP2pSpecifiedType == 4` :
  la configuration transmet `CameraInfoBean.getId` à
  `ConfigCameraBean.setP2pId`, récupère
  `CameraInfoBean.getP2PConfigStr` et la transmet à
  `ConfigCameraBean.setToken`, puis renseigne le `skill`.
  **Cette branche ne consulte pas `CameraInfoBean.getP2pId`.**
- `getP2pSpecifiedType == 2` :
  la configuration consulte `getP2pId`,
  `getP2PConfigInitStr` et `getP2PConfigKeyStr`,
  avec une construction de la chaîne d'initialisation.
- `getClientTid` construit localement une chaîne contenant
  `System.currentTimeMillis()`. Son absence du retour API
  n'est pas un indice d'échec.

La documentation Tuya traite les différents fournisseurs P2P comme
des implémentations distinctes. Un ancien changelog officiel précise
également que la génération de `p2pId` varie entre les types 2 et 4.

**Important :** le `skills.p2pType=4` remonté par Tuya et le
`p2pSpecifiedType` de `CameraInfoBean` ne sont pas nécessairement
le même champ. La bêta38 prouvait la présence du second, pas sa valeur.

## Changement bêta39

Le bouton **Préparation SDK** de la bêta38 effectue strictement les
mêmes lectures, sans nouvelle API et sans requête de session-init.

Il affiche désormais, uniquement pour les deux réponses RTC :

- la catégorie **à valeur autorisée** de `p2pSpecifiedType` :
  `thing_4`, `p2p_2`, `tutk_1`, `autre` ou `absent` ;
- la présence d'un `id` **à la racine de la fiche RTC**, et
  non un `id` provenant du sous-objet `session`, ICE ou relais ;
- si les trois champs structurants de la branche **type 4**
  sont simultanément visibles : `p2pSpecifiedType=4`,
  `id` racine et `p2pConfig`.

Un drapeau de cohérence n'est **pas** une preuve de création native
`ThingIPCSdk`, d'identification AOSU/Tuya, de parité avec
le code Python ni de réception du SDP.

Aucune valeur privée (ID, chaîne de configuration, token, clé locale,
mot de passe, adresse, SN, identifiant de session) n'est retournée.

## Prochain test réel

1. Installer `0.8.13-beta39`, redémarrer Home Assistant puis Ctrl+F5.
2. Cliquer **une seule fois** sur **Préparation SDK** de la C9C autonome.
   Ne pas cliquer Fiche Tuya, Fiche AOSU, réveil ou vidéo.
3. Transmettre le message anonymisé, particulièrement
   `SDK classique : p2pSpecifiedType`,
   `id racine RTC` et `branche Thing-4 cohérente`.

Si type 4 et ID de fiche sont présents, on aura identifié
une **différence concrète** entre le chemin SDK Android et notre
chemin de préparation vidéo Python. Cela ne suffit pas à autoriser
une publication MQTT à destination de la caméra : la correspondance
du destinataire et les détails du protocole doivent être vérifiés.

Si type 4 est présent mais `id` absent, on examinera
son origine dans le `DeviceBean` / mapping de réponse du SDK
plutôt que d'inventer un P2P ID.

## Tests et protection de l'existant

`tests/test_c9c_thing4_branch_b39.py` vérifie les branches,
la non-confusion avec les ID ICE, l'absence de secrets et de
commandes réelles.

La C5L et les deux C9C3CA11 reliées à H1L, leurs vidéos,
leurs PTZ et les entités Home Assistant restent inchangés.

### Références publiques

- Tuya SDK IPC — choix du fournisseur P2P :
  https://developer.tuya.com/en/docs/app-development/homedevice?id=Kceuhbr6hms0u
- Tuya SDK Android — paramètres de création P2P :
  https://tuyainc.github.io/tuyasmart_camera_android_sdk_doc/en/resource/ICameraP2P.html
- Changelog Tuya — différence p2pId type 2 / type 4 :
  https://images.tuyacn.com/goat/pdf/01JQWNFB9AE0H4ADYKEE2TE33W/Changelog_Smart%20App%20SDK_Smart%20App%20SDK.pdf
