# Smart AOSU C9C autonome — correction expérimentale de la configuration RTC et des identifiants d'authentification média

**13 novembre 2026 — branche `fix/c9c-thing4-rtc-password-provenance`**  
**Ne pas installer : `main` reste en `0.8.13-beta43`.**

## Anomalie 1 : la mauvaise API RTC est utilisée pour la vidéo autonome

Dans `custom_components/smart_aosu_cloud/tuya_rtc_inventory.py`,
le chemin **vidéo active C9C autonome** (`standalone_c9c_video_test`)
demandait `m.ipc.v4.rtc.config.get`.

Dans l'APK AOSU 5.10.12 complète, le parcours
`ThingSmartCameraP2PSync.requestCameraConfig` →
`CameraBusiness.requestCameraInfo` interroge
`thing.m.rtc.config.get`, puis prépare une instance native
fournisseur **Thing-4**. Les bêtas38 et 39 ont montré que les
deux API répondent et portent une configuration `p2pConfig`.
Elles **ne** prouvent pas que les deux sessions, politiques et
authentifications soient interchangeables.

**Correction :** la vidéo active C9C demande désormais
`thing.m.rtc.config.get`, sur la même clé de périphérique,
avec les mêmes contrôles de sélection stricte et de fraîcheur
des données. Les lectures explicitement IPC-v4, la sonde
WeRTC et le réveil seul conservent IPC-v4. Le fonctionnement
historique de la C5L et des C9C/H1L utilise toujours la
configuration RTC classique et ne change pas.

Ce changement n'appelle ni `thing.m.rtc.session.init`, ni
un endpoint nouveau : l'API classique était déjà autorisée
et confirmée en lecture.

## Anomalie 2 : un mot de passe caméra déjà fourni est perdu

Le constructeur `inspect_rtc_media` produisait précédemment :

```python
device_password=raw.get('password', '')
```

Or les réponses API Tuya sont structurées, souvent
`{data: {password: "...", p2pConfig: ...}}`. La
**bêta38 a attesté la présence d'un mot de passe dans la RTC
classique** mais cela ne prouve pas qu'il était à la racine
du JSON passé à Python.

Un objet média pouvait donc être créé avec
`device_password = ""` alors que le serveur renvoyait un
secret non vide. Cet objet rejoint
`tuya_relay_handshake → tuya_kcp_probe →
tuya_channel0_probe.run_media_start`, où l'authentification
du canal zéro calcule notamment
`MD5(device_password + "||" + localKey)`.

Un mot de passe vide peut rendre cette authentification
invalide, **une fois le transport établi**.

**Correction :** un extracteur C9C-only considère uniquement
les enveloppes `root`, `root.data`, `root.result` et
l'unique couche `data/result` en dessous ; il rejette
les valeurs absentes, trop longues, malformées ou contradictoires.
Il n'interroge pas les objets `session`, `p2pConfig`,
`relay`, `deviceInfo` ni une quelconque donnée privée
d'un autre appareil.

Les valeurs sont transmises **seulement** dans l'objet
`PrivateMediaBootstrap` en RAM. Ni la carte Home Assistant
ni les services n'exposent le mot de passe, le `devId`,
le SDP, la clé locale, l'UID ou un token.

**Isolation :** le nouveau paramètre
`standalone_c9c=False` laisse les parcours C5L et H1L
inchangés, y compris les règles de traitement du JSON.

## Preuves et limites

- Les tests de la branche exécutent le **vrai parseur Python**
  avec des réponses synthétiques où le mot de passe
  se trouve sous `data.password`.
- Ils vérifient aussi que le condensat MD5 d'authentification
  diffère de celui calculé avec la chaîne vide, que le rapport
  est anonymisé, et que l'ancien chemin reste inchangé.
- Les tests de sélection RTC évaluent les branchements réels
  pour les chemins vidéo, lecture seule et réveil.
- **Ces tests ne démarrent pas la C9C** et ne prouvent
  ni liaison AOSU SN ↔ Tuya `devId`, ni acceptation SDP,
  ni parité native Thing-4.
- La correction du mot de passe est pertinente **après**
  l'obtention d'un SDP answer et la création du transport.
  Elle ne peut donc pas expliquer, à elle seule,
  l'absence de SDP answer lors des essais précédents.
- De même, l'API RTC classique est celle empruntée par
  le code Android étudié, mais sa sélection dans Python
  ne constitue pas une réimplémentation du SDK natif.
- Les offres à cible uniquement heuristique
  **restent bloquées** : aucun déverrouillage automatique.

## Politique de publication

Ce correctif demeure sur une **branche de développement**.
Ne pas publier de bêta44 ni demander de nouveaux essais
de présence de champs. Avant toute mise à jour matérielle,
il faut conserver le verrou d'identité et démontrer un
chemin de session compatible avec le SDK Thing-4. Toute
expérience vidéo future doit être unique, explicitement
autorisée et limitée à la caméra autonome.

Les trois caméras déjà fonctionnelles, leurs entités et
leurs commandes PTZ ne sont pas modifiées.

### Fichiers

- `custom_components/smart_aosu_cloud/tuya_media_bootstrap.py`
- `custom_components/smart_aosu_cloud/tuya_rtc_inventory.py`
- `tests/test_c9c_rtc_password_provenance.py`
- `tests/test_c9c_rtc_v4_video.py`
- `tests/test_c9c_rtc_v4.py`
