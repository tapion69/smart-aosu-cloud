# C9C autonome — génération du connect_session et voie HTTP native Thing-4

**13 novembre 2026 — recherche hors ligne sur la branche `experiment/c9c-native-session-contract`, sans nouvelle bêta Home Assistant.**

## Origine, méthode et limites

Archive originale AOSU 5.10.12 fournie par le propriétaire, SHA-256
`ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7`.
Analyse de `libThingP2PSDK.so` AArch64 avec ELF64 + désassemblage statique et vérification des instructions ; aucun appel au SDK, aux caméras ou au réseau. Aucun secret, numéro de série, paquet, SDK binaire ni identifiant utilisateur commité.

**Cette analyse démontre des chemins présents dans le SDK, pas quelle branche est effectivement exécutée lors de l'ouverture de la C9C autonome.**

## 1. Un identifiant `connect_session` est généré dans le moteur natif

Le binaire contient les trois commandes internes :
- `connect` ;
- `connect_v2` ;
- `connect_v3`.

Dans les trois fonctions respectives `imm_p2p_rtc_connect`, `imm_p2p_rtc_connect_v2`, `imm_p2p_rtc_connect_v3`, l'instruction `mov w1, #33` précède un appel **effectif** à `imm_p2p_misc_rand_string`. Le tampon généré est passé à la construction JSON de la commande, dont le modèle contient `"connect_session":"%s"`.

Preuves du build exact, vérifiées par décodage AArch64 BL et lecture des chaînes de format :

| Fonction native | Taille passée à `rand_string` | Adresse de l'appel | Fonction appelée |
| --- | --- | --- | --- |
| `imm_p2p_rtc_connect` | 33 | `0x60A88` | `imm_p2p_misc_rand_string@plt` |
| `imm_p2p_rtc_connect_v2` | 33 | `0x60D84` | `imm_p2p_misc_rand_string@plt` |
| `imm_p2p_rtc_connect_v3` | 33 | `0x6105C` | `imm_p2p_misc_rand_string@plt` |

Les trois appels pointent vers `0x40E20`. **On peut donc démontrer la génération locale d'un identifiant de connexion natif**, dans un tampon de 33 octets (sans supposer que tous les caractères soient nécessairement utilisés). Cela n'implique pas qu'il soit le même que le `sessionid` visible dans un message MQTT officiel.

## 2. Une étape d'offre HTTP existe également dans la bibliothèque

Le binaire contient l'API littérale `thing.m.rtc.session.offer_1.0`. Le désassemblage repère sa **référence réelle** au sein d'une construction cJSON (`0x69D48–0x69D50`), puis la sérialisation et l'insertion d'un message dans une file interne (`0x69DB0`, `0x69F5C`).

Cela confirme un **chemin natif de préparation / routage de requête d'offre RTC**, plus riche qu'un simple `sigQry(22) + offer(302)` sur notre socket MQTT.

**Précautions nécessaires :**
- Ce constat ne démontre pas que l'API soit toujours sollicitée pour une C9C Thing-4.
- La présence d'un chemin d'offre dans l'exécutable ne révèle ni les paramètres complets ni les réponses attendues dans cette installation.
- Il ne faut **pas** ajouter immédiatement `thing.m.rtc.session.offer_1.0` au client Python sans en comprendre les conditions et effets (création de session/état côté cloud).

## 3. Trois identifiants à ne plus confondre

| Élément | Origine connue | Utilisation connue | Correspondance native prouvée ? |
| --- | --- | --- | --- |
| `p2pConfig.session.sessionId` | Configuration RTC Tuya | SDP et `header.sessionid` dans l'offre Python actuelle | Valeur reçue du cloud, oui ; parité native complète non |
| `tcp_token.sessionId` | Rendez-vous construit localement par le client Python | Authentification du relais TCP/KCP | Conforme à la référence Python MIT, pas prouvé identique sur la C9C |
| `connect_session` | Générateur natif `imm_p2p_misc_rand_string` | Argument des commandes internes natives `connect`, `connect_v2`, `connect_v3` | **Génération et transport dans commande prouvés ; liaison au `header.sessionid` MQTT inconnue** |

L'observation de la **bêta12** reste déterminante : pendant un direct ouvert avec l'application officielle, les 18 messages observés ont pu être déchiffrés, dont une `answer` et des `candidate` 302. Notre propre session Python n'a jamais reçu son `answer`. **Ne pas présenter la réponse de l'application officielle comme celle de Home Assistant**.

## 4. Outil vérifiable ajouté, sans APK dans GitHub

- `tools/aosu_c9c_native_connect_session_offline.py` : analyse exclusivement l'APK locale d'empreinte fixée ; vérifie les trois appels de génération d'identifiant, les trois modèles de commande, la référence de l'action native et son chemin cJSON/file. Il ne renvoie que des booléens fixes.
- `tests/test_aosu_c9c_native_connect_session_offline.py` : six tests à partir d'un **ELF entièrement synthétique**, pas de SDK propriétaire dans GitHub Actions.
- `.github/workflows/aosu-c9c-native-connect-session.yml` : vérification CI exécutée sur la branche expérimentale.
- Tests synthétiques **réussis** : [GitHub Actions run 43498901089](https://github.com/tapion69/smart-aosu-cloud/actions/runs/43498901089).
- Analyse indépendante sur l'extraction locale réelle : trois appels générant `connect_session`, trois modèles de commande, et deux ancrages de la préparation de requête HTTP confirmés.

## 5. Seule étape suivante techniquement justifiée

Tracer, toujours **hors ligne**, l'enchaînement entre la commande `connect_v3` / `connect_v2`, la création d'une session native et l'API `thing.m.rtc.session.offer_1.0` ; déterminer à quel moment sont associés les champs `connect_session` et `sessionid` utilisés sur la signalisation réelle. La question prioritaire est l'éventuelle divergence de **procédure de session**, pas une constante AES/CRC, un numéro de caméra deviné, ni une valeur `p2p_skill` à changer.

Tant que cette relation et l'identité AOSU↔Tuya de la C9C extérieure ne sont pas établies, **aucune offre MQTT de test ni bêta44 ne doivent être préparées**. Les 3 caméras historiques C5L / 2×C9C-H1L (vidéo, PTZ, entités) et `main` `0.8.13-beta43` sont préservées.

**Nature de la conclusion :** découverte architecturale et preuve binaire reproductible, **pas une correction vidéo déjà fonctionnelle**.
