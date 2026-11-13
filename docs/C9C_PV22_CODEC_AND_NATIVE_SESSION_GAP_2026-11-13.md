# Smart AOSU — Bilan du codec MQTT 2.2 et blocage de session Thing-4

**13 novembre 2026 — audit hors ligne, aucune nouvelle bêta Home Assistant**

## Objectif

Ne plus multiplier les diagnostics inutiles pour la C9C autonome. Isoler
l'écart effectif entre la connexion officielle AOSU et le moteur Python,
en réutilisant l'APK complète AOSU 5.10.12 déjà fournie, les captures
passées et le code du dépôt. Aucune opération sur la caméra.

## Nouveaux résultats confirmés sur les DEX de l'APK

L'APK complète (SHA-256 vérifié dans l'outil d'analyse) contient un
encodeur `MqttControlBuilder` utilisé par la chaîne de signalisation
Tuya. Le choix de version ne provient pas d'une constante immuable :
`DeviceBean.getPv` est consulté, puis
`ThingUtil.checkPvVersion` sélectionne un encodeur spécifique.

Dans `classes5.dex`, la version 2.2 est associée à la méthode
obfusquée `qpbpqpq.bdpdqbp`. L'instruction de sélection contient
le flottant 2.2 (0x400CCCCD). L'analyse de l'APK originale constate
**7 éléments sur 7** :

1. sélection explicite du chemin 2.2 ;
2. encodeur propre à cette version ;
3. création d'un `PublishBean2_2` avec les champs
   `data`, `protocol`, `t` ;
4. sérialisation `Fastjson.JSON.toJSONString` ;
5. `AESUtil.setALGO("AES")` puis `encryptWithBytes` ;
6. calcul d'un CRC32 sur les octets de séquence, de source et
   de données chiffrées ;
7. assemblage avec le préfixe de version et les octets
   de séquence/source.

Côté Python, `tuya_mqtt_offer._signal_frame` prépare un JSON
`{data,protocol,t}`, chiffre en AES-ECB avec bourrage PKCS#7,
et construit `2.2 + CRC32 + S + O + ciphertext`.

**Comparaison :** structurellement, l'enveloppe 2.2 est cohérente.
Aucune différence structurelle prouvée ne justifie son remplacement.
L'identité octet-à-octet entre Fastjson Android et Python n'est
pas démontrée, car nous ne possédons pas de vecteur d'émission
enregistré par l'application officielle.

### Ce que les données réelles montrent déjà

La bêta12 avait déchiffré 18/18 publications de la session
lancée dans l'application officielle AOSU. Parmi elles figuraient
des messages 302 `answer` et `candidate` envoyés par le
périphérique Tuya candidat et adressés à l'UID de l'utilisateur,
avec SDP AES/KCP. Cela prouve au minimum que la clé locale
et le décodeur 2.2 permettent de lire cette signalisation officielle,
et constitue un rapprochement opérationnel fort du périphérique
Tuya avec le direct consulté. Il ne relie pas cryptographiquement
le numéro de série AOSU au `devId`.

Le moteur HA, lui, a reçu un PUBACK sur son offre, **pas**
une réponse SDP de sa propre session. Il serait donc inexact
de présenter le codec 2.2 seul comme la cause établie.

## Blocage principal : la machine de session native

Les symboles ELF ARM64 de `libThingP2PSDK.so` comprennent :

- `ThingP2PInitialize`, `ThingP2PInit` ;
- `ThingSmartP2PSDK::thing_p2p_rtc_pre_connect_v2` ;
- `ThingSmartP2PSDK::thing_p2p_rtc_connect_v2` et
  `thing_p2p_rtc_connect_v3` ;
- `ThingSmartP2PSDK::OnSessionStateChanged` ;
- `ThingSmartP2PSDK::SendMessageThroughMQTT` et
  `SendMessageThroughLAN` ;
- `ThingP2PSetSignaling`, `ThingP2PSetHttpResult`,
  `ThingP2PSetSignalingSendResult`.

La couche Java sélectionne entre publication locale et MQTT,
récupère `DeviceBean`, `pv` et `localKey`, puis transmet
les messages 302 à la couche appropriée.

Le code Python `tuya_mqtt_offer._probe` fait surtout :
`MQTT TLS -> subscribe -> sigQry (22) -> offer (302) ->
candidate ICE éventuel -> attente answer -> relais/KCP`.

Il **ne** possède pas l'équivalent de la pile
`ThingP2PInitialize` / `ThingP2PConnect_v2/v3` et de la
machine de callbacks native. Cette distinction est prouvée
au niveau du code ; elle n'établit pas quelle sous-routine
C++ particulière la C9C a utilisée pendant sa session
officielle.

L'API `thing.m.rtc.session.init` figure également dans
le DEX, mais **il n'est pas démontré** qu'elle soit obligatoire
pour cette caméra. Le chemin `requestCameraConfig` étudié
emploie `thing.m.rtc.config.get`. Ne pas ajouter
`session.init` par supposition : cela pourrait créer
des sessions côté cloud et n'apporte pas de parité native.

## Décisions concrètes

1. **Ne pas réécrire l'AES/CRC32 2.2 sans vecteur contraire.**
   La partie structurelle est validée sur l'APK réelle.
2. **Ne pas inventer d'identité CP.** Les réponses HTTP AOSU
   et Tuya n'ont pas établi un pont SN↔devId ; la session
   officielle déchiffrable fournit une observation plus
   forte, sans suffire à certifier le numéro de série.
3. **Isoler l'initialisation/protocole P2P Thing-4** :
   déterminer les états nécessaires, les obligations de
   préconnexion, et les messages signalés par les
   callbacks, avant de modifier une émission 302.
4. **Pas de nouvelle expérience physique** tant qu'il
   n'existe pas une différence de session démontrable
   et une correction testable hors ligne.
5. Conserver `0.8.13-beta43`. Les vidéos et PTZ de la
   C5L et des deux C9C/H1L restent inchangés.

## Travaux de code effectués

L'outil existant
`tools/aosu_native_302_routing_offline.py` analyse maintenant,
en plus du routage Java/natif, les DEX 5 et 6 et
les exportations de **préconnexion et connexion v2/v3**.
L'APK fournie par l'utilisateur reste locale ; GitHub Actions
exécute uniquement des fixtures synthétiques.
La vérification locale, sur l'APK originale, a confirmé les
sept étapes du codec 2.2. Ce résultat **n'est pas** un test
matériel de la vidéo C9C.

### Références de mise en œuvre

- `custom_components/smart_aosu_cloud/tuya_mqtt_offer.py`
  : émetteur Python de référence.
- `tools/aosu_native_302_routing_offline.py`
  : vérification statique version, codec et callbacks.
- `tests/test_aosu_native_302_routing_offline.py`
  : assertions sans réseau, caméra ni APK OEM.
- `docs/C9C_NATIVE_THING4_SIGNAL_ROUTING_AUDIT_2026-11-13.md`
  : routage LAN/MQTT déjà documenté.
- Documentation officielle Tuya SDK Android :
  https://developer.tuya.com/en/docs/app-development/livestream?id=Ka6nuvynnjk7h

**État actuel : architecture et cause probable mieux isolées,
mais vidéo C9C autonome toujours non opérationnelle.**
