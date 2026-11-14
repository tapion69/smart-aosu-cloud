# Smart AOSU — faisabilité du client Thing-4 sur Home Assistant Linux

**13 novembre 2026 — branche `experiment/c9c-native-session-contract` ; aucune nouvelle bêta.**

## Résultat important : le problème ne se règle pas par un copier-coller du SDK Android

Le propriétaire a fourni l'archive complète AOSU 5.10.12, SHA-256
`ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7`.
Les bibliothèques ont été **inspectées localement sans exécution**, notamment avec `readelf`.

| Bibliothèque | Architecture ELF | Dépendances observées |
| --- | --- | --- |
| `libThingP2PSDK.so` | AArch64 / ARM64 (ELF64, machine 183) | `libandroid.so`, `liblog.so`, `libc.so`, `libc++_shared.so`, etc. |
| `libThingCameraSDK.so` | AArch64 / ARM64 | `libThingP2PSDK.so`, `libThingAudioEngineSDK.so`, `libThingVideoCodecSDK.so`, `liblog.so`, etc. |

**Conclusion vérifiée :** ce moteur natif exige une ABI ARM64 et des composants du runtime Android/Bionic. Il n'est pas directement chargeable dans Home Assistant OS **x86-64**. Un éventuel support ARM64 de Home Assistant ne suffirait pas, car les dépendances Android sont également nécessaires. Les exportations JNI ne fournissent pas une API Linux cliente autonome documentée.

### Contrôle reproductible créé

- `tools/aosu_c9c_client_abi_portability_offline.py` : vérifie le SHA de l'APK locale et lit les sections ELF `DT_NEEDED` / machine sans charger le code ; affiche uniquement des **booléens fixes**, jamais de noms privés, clés, identifiants, paquets ni contenu OEM.
- `tests/test_aosu_c9c_client_abi_portability_offline.py` : six cas de régression uniquement à partir d'ELF synthétiques construits en mémoire, dont bibliothèques Android ARM64, absence de dépendances, fichier tronqué et sections `NOBITS`.
- `.github/workflows/aosu-c9c-client-abi-offline.yml` : lance uniquement ces tests synthétiques. **CI réussie**, run [43490506089](https://github.com/tapion69/smart-aosu-cloud/actions/runs/43490506089).
- **Aucune APK ou bibliothèque propriétaire n'a été transférée dans GitHub**. L'analyse `readelf` des véritables .so et la réussite CI des fixtures sont deux vérifications différentes ; ne pas les confondre.

## Étude des voies Linux réellement documentées

1. **TuyaOpen / TuyaOS Linux P2P** : expose `TUYA_APP_Start`, `p2p_init`, `p2p_rtc_listen_start`, et des callbacks alimentant des images de caméra. C'est un service **côté appareil IPC**, pas un client qui ouvre la vidéo d'une C9C depuis Home Assistant. Le port direct ne résout pas notre problème.
   Références : https://docs.tuyaopen.ai/docs/tuyaopen-core/p2p-api et
   https://developer.tuya.com/en/docs/iot-device-dev/IPC_SDK?id=Kaqe10hg0htn5.
2. **Tuya Smart App SDK Android** : `createCameraP2P → connect(callback) → startPreview(callback)`, avec dépendances NDK `arm64-v8a` / `armeabi-v7a` ; pas d'artefact Linux client x86-64 présenté dans la documentation consultée. Les API HarmonyOS exigent aussi un environnement applicatif et l'initialisation du MQTT avant `initP2P`.
   Références : https://developer.tuya.com/en/docs/app-development/livestream?id=Ka6nuvynnjk7h ,
   https://developer.tuya.com/en/docs/app-development/preparation?id=Ka8j28bt6i7eo ,
   https://developer.tuya.com/en/docs/app-development/ipc?id=Kf5fxtjv15t98.
3. **`roquerodrigo/tuya-ipc-p2p-sdk` (MIT, Python indépendant)** : fournit déjà MQTT 302, ICE, relais TCP/KCP, canal zéro et MJPEG sans lancer un SDK propriétaire. **Notre code reprend déjà ce principe.** Son README le décrit comme alpha, validé principalement sur un autre matériel MJPEG, région US, pas sur C9C européenne. Ce n'est donc pas une solution prête à installer.
   Référence : https://github.com/roquerodrigo/tuya-ipc-p2p-sdk.

## Ce qui reste réellement inexpliqué pour la C9C autonome

- **Identité** : la bêta12 a déchiffré 18/18 messages officiels, dont une SDP answer de la session officielle, et l'expéditeur Tuya candidat. Cela renforce le lien opérationnel mais ne prouve pas le pont SN AOSU ↔ devId pour un envoi actif.
- **Session** : HA a seulement obtenu des PUBACK pour ses offres ; aucune answer à **sa propre** session, aucun flux vidéo.
- **Données SDK** : la branche native Thing-4 construit un `ConfigCameraBean` avec l'identifiant P2P type 4, la politique, les capacités, les métadonnées de session et le JSON complet `CameraInfoBean`, puis appelle `setCameraConfig/connect`. Notre SDP / MQTT ne prouve pas la reproduction de ce contrat.
- **Transport** : routage MQTT ou LAN commandé par l'état natif ; aucune preuve de la branche effectivement choisie durant le direct C9C.
- **Corrections déjà réunies ici** : RTC classique Thing-4 pour le direct C9C et extraction bornée du mot de passe caméra, sans effet sur C5L/H1L. Ces correctifs précèdent l'authentification du canal vidéo ; ils ne prouvent pas une réponse SDP.

## Décision pour le développement

**Voie retenue : client Python indépendant, C9C autonome exclusivement, sur branche expérimentale.** Ne pas tenter de faire tourner les bibliothèques Android extraites dans Home Assistant ; ne pas prendre le code Linux **côté appareil** pour un client vidéo ; ne pas réécrire AES/CRC ni ajouter `session.init` sans preuve.

L'enquête encore utile est limitée à une question décisive : *quels arguments/états du connecteur natif aboutissent à une offre C9C type 4 réellement acceptée, et peut-on les reconstruire proprement sur Python ?* Le fait d'avoir identifié `ConfigCameraBean` ne démontre pas la suffisance d'un paquet MQTT.

Les prérequis d'un prochain essai restent :
(a) une identité de cible exacte,
(b) une différence prouvée et corrigeable dans la négociation,
(c) les tests hors ligne et de non-régression réussis,
(d) un unique essai utilisateur consenti. **Pas de nouvelle bêta44 pour des diagnostics répétés.**

**Protection des acquis :** `main` reste en `0.8.13-beta43`. Aucun changement aux entités, au direct ou au PTZ des trois caméras C5L/C9C-H1L ; aucun secret, APK, log ou paquet privé dans le dépôt.
