# Smart AOSU — Verrous natifs de l'offre HTTP et décision de routage C9C

**14 novembre 2026 — analyse sur APK originale 5.10.12, sans connexion ni commande.**

## Nouvelle preuve : huit conditions de la machine d'états (vérifiées sur l'APK réelle)

Outil : `tools/aosu_c9c_native_http_gates_offline.py` — APK originale SHA-256
`ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7`.
Binaire `libThingP2PSDK.so` SHA-256
`c9032dcf37f72fc7ad28835a02c4e66a814597380f10c132d042df78969f1745`.

Exécution locale de l'outil sur l'APK : **8/8 vérifications positives**. Les vérifications contrôlent les opcodes ARM64 et, pour les branches et appels, leurs **véritables destinations**. Aucun secret ou code propriétaire n'est distribué sur GitHub.

| Preuve native vérifiée | Adresses ARM64 |
| --- | --- |
| L'entrée RTC lit un état à +0xe58 et sort immédiatement quand cet état vaut 1 | 0x69998–0x699a8 |
| Un pointeur d'état de transport à +0x3268 contrôle la branche | 0x699ac–0x699b4 |
| Un drapeau de demande déjà engagée à +0xe1c évite les doublons ; il est ensuite fixé à 1 | 0x699d8–0x699dc ; 0x69a90–0x69a94 |
| Le délai natif d'attente est 15 000 ms | 0x69a9c–0x69aa4 |
| Un contexte P2P à +0x3c8 doit être non nul | 0x69a84 ; 0x69aa8–0x69aac |
| `imm_p2p_rtc_sdp_encode` est appelé après les gardes, et son échec fait bifurquer | 0x69ad4–0x69ad8 |
| L'offre est déposée en file comme type de message 5, **après** encodage | 0x69f50–0x69f5c |
| Le drapeau utilisé pour `is_pre` est mis à 1 ou 0 au cours des transitions précédentes | 0x66668 ; 0x66900 ; 0x66c2c ; 0x66d4c |

**Interprétation :** la demande native HTTP n'est pas émise depuis une simple lecture RTC JSON. Elle est conditionnelle à un état de transport initialisé et à des données de session déjà chargées. L'action manuelle actuelle HA `tester_offre_http_thing4_c9c` ne reproduit **pas** cette machine d'états. Ainsi, deux refus HTTP observés ne peuvent pas être imputés à l'en-tête JSON seul.

Cela ne prouve **ni** que le HTTP est le transport réellement choisi par la C9C du frère, **ni** la cause précise de son refus. Le type de routage demeure à confirmer par des preuves compatibles avec sa configuration.

## Nouvelle vérification : présence de `thing.m.rtc.session.init`

Dans `classes6.dex`, le SDK Android `CameraBusiness` comporte :

- `requestCameraInfo` (surcharge méthode 4281) qui prépare `thing.m.rtc.session.init` version `1.0` et règle le domaine métier `ipc` ;
- `requestCameraInfo` (surcharge méthode 4282) qui prépare **`thing.m.rtc.config.get`** version `1.0` et règle aussi `ipc` ;
- `requestCameraSessionInit` (méthode 4283), qui prépare aussi `thing.m.rtc.session.init`.

La méthode `ThingSmartCameraP2PSync.innerConnect` appelle `requestCameraConfig`, qui invoque la **surcharge 4282 / config.get** ; son chemin n'invoque pas directement `session.init`. Une recherche statique des appels directs vers `ThingSmartCameraP2PSync.requestCameraSessionInit` dans **les 17 DEX** de l'APK complète n'a trouvé aucun appel direct. Cela ne couvre pas une éventuelle invocation indirecte ou dynamique.

**Conséquence :** ne pas ajouter `thing.m.rtc.session.init` comme nouvelle étape obligatoire de Home Assistant en se fondant seulement sur sa présence dans le SDK. Cette API pourrait modifier une session distante, et sa nécessité pour **cette** C9C n'est pas démontrée.

## Confirmation par documentation externe

La documentation officielle Tuya de la couche P2P distingue la **configuration cloud et l'activation d'un produit IPC**, l'initialisation du moteur P2P, la signalisation cloud/LAN et l'établissement du média. Elle demande d'initialiser le P2P après connexion MQTT du dispositif et d'employer une catégorie de produit IPC :
https://docs.tuyaopen.ai/docs/tuyaopen-core/p2p-api

Cela **ne permet pas** de conclure que la C9C du frère est mal classée : son identité AOSU↔Tuya n'est toujours pas prouvée. C'est une piste de validation des métadonnées plutôt qu'une raison de modifier l'API arbitrairement.

La documentation Tuya Android décrit également l'initialisation P2P liée à l'UID utilisateur :
https://developer.tuya.com/en/docs/app-development/android-p2p?id=Kalemnh8lf8yi

## Travail GitHub

- `tools/aosu_c9c_native_http_gates_offline.py` : analyse hors ligne épinglée à l'APK et à l'ELF exacts, en mémoire uniquement.
- `tests/test_aosu_c9c_native_http_gates_offline.py` : huit tests synthétiques incluant mutations de branche, de contexte, de délai, de garde d'offre et de queue.
- `.github/workflows/c9c-native-http-state-gates.yml` : CI sans APK ni bibliothèques OEM.
- Exécution **réelle** locale : huit preuves sur huit établies, sans réseau.
- CI synthétique :
  https://github.com/tapion69/smart-aosu-cloud/actions/runs/43586925719

## Conséquences pour la suite

1. **Suspendre** toute nouvelle offre HTTP de type `tester_offre_http_thing4_c9c` : elle ne reproduit pas le moteur P2P AOSU et a déjà été refusée deux fois.
2. **Priorité A** : confirmer le lien typé exact AOSU SN / `cpUuid` / Tuya devId sans l'assimiler à un simple candidat unique. Le SN de l'application officielle correspond au SN AOSU de HA, **mais ce n'est pas un lien Tuya**.
3. **Priorité B** : produire un adaptateur de session qui respecte la bonne branche de connexion (LAN ou MQTT/HTTP selon configuration réelle), le chargement des jetons, la préparation SDP/ICE et l'état de préconnexion, plutôt que d'émettre directement des messages `offer` synthétiques.
4. **Priorité C** : ne lancer un test matériel qu'après une modification qui traite **effectivement** ces préconditions. Un nouveau simple appel HTTP, même avec un nouveau champ, n'est pas informatif.

**`main` et la version installable `0.8.13-beta44-rc3` ne sont pas modifiés. La vidéo/PTZ C5L et deux C9C sur H1L restent hors du chantier.** Aucun test matériel ou vidéo réel n'a été effectué dans cette étape.
