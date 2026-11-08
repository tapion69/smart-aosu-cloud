# Smart AOSU — traçage des appels MQTT et de la signalisation caméra

**8 novembre 2026 — analyse statique de l'APK AOSU 5.10.12 complet.**

## Source et méthode

APK original AOSU 5.10.12, SHA256 vérifié (empreinte connue du projet),
17 fichiers DEX. Analyse locale des tables `method_ids`, `class_defs`,
`class_data` et des instructions Dalvik `invoke-*`. Aucune caméra,
aucun réseau, aucun compte et aucun secret utilisés. Les chaînes et les
valeurs privées des ressources propriétaires restent hors dépôt.

Le diagnostic beta25 sur Home Assistant portait sur l'APK allégé (1 DEX) ;
son absence d'indices Jarvis/MSID était donc inconclusive. Le compte rendu
précédent est `docs/AOSU_SDK_MQTT_APK_COMPLET_2026-11-08.md`.

## 1. Initialisation MQTT du SDK

Dans **classes5.dex** :
- `Lcom/thingclips/sdk/mqtt/bqbppdq;->init` (method_id **6451**)
  appelle `IThingGetBaseConfig.getMqttConfigInfo`, puis
  `initMqttConfig` et `initMqtt`.
- `bqbppdq;->initMqttConfig` (method_id **6453**) consomme
  `MqttConnectConfig.getUid/getAppTag/getAccessId/getTerminalId/getConnectMethod`,
  `BaseConfigInfo.getDomain` et `Domain.getMobileMqttsUrl`.
  Il initialise `MqttConfigBean` (client ID, username, options MQTT,
  SSL et mot de passe). La **valeur réelle** de ces champs n'est pas
  extraite ni publiée.
- `bqbppdq;->connect` (method_id **6449**) appelle `init`, puis
  `pqpbdqq.connect` ; `pqpbdqq.realConnect` appelle ensuite
  `pqdbppq.connect`.

Dans **classes4.dex**, `Lcom/thingclips/sdk/device/qqpqqpq;`
(methods **34155** et **34164**) appelle
`IThingGetBaseConfig.getMqttConfigInfo`, puis obtient le serveur par
`IThingMqttPlugin.getMqttServerInstance`, lui affecte
`setMqttConfigTransfer` et appelle `IMqttServer.connect`.
Cela établit une chaîne d'appel vérifiable vers le client MQTT du SDK.

## 2. Réveil et signalisation de caméra

Dans **classes6.dex**,
`Lcom/thingclips/smart/p2p/qqpddqd;` (nom obfusqué) :
- `publishWirelessWake` (method_id **13285**) appelle
  `IThingMqttPlugin.getMqttServerInstance` et `IMqttServer.publish`.
- `registerCameraP2P302Listener` (method_id **13287**) appelle
  `IMqttServer.registerMqttMessageParserListener`.
- Les surcharges `publish` (method_ids **13283** et **13284**)
  consultent `SandRMap`, construisent un `MqttControlBuilder` et
  renseignent explicitement `setData`, `setLocalKey`, `setPv`,
  `setProtocol`, `setTopicId`, `setSn`, `setO`,
  `setS` et `setT` (horodatage), puis appellent
  `IMqttServer.publishDevice`.

Dans **classes5.dex**,
`Lcom/thingclips/sdk/mqtt/bqbppdq;->publishDevice`
(method_id **6465**) :
- vérifie la connexion et l'abonnement MQTT ;
- utilise les familles de sujets `smart/mb/in/` et
  `smart/mb/out/` ;
- lit les propriétés du `MqttControlBuilder` avant de passer
  à des classes d'encodage internes du SDK
  (`bddqqbb`, `bqqppqq`).

Dans **classes16.dex**, `TyDeviceCenter` obtient le
`getMqttServerInstance`, enregistre un callback MQTT et reçoit
`onConnectSuccess` et `onConnectError`.
Le fait que ces classes soient embarquées ne démontre **pas** que
la C9C autonome utilise exclusivement ce chemin.

## 3. Écart avec notre implémentation Python

Le moteur actuel `tuya_mqtt_offer.py` :
- publie sur `smart/mb/out/{device_id}` ;
- construit son enveloppe 2.2 avec `sequence` 1 puis 2 et
  une source de quatre octets aléatoires ;
- crée sa propre structure `_signal_frame` (CRC32, chiffrement,
  payload JSON).

Le SDK Android maintient en revanche un **état SandRMap/SandO**
et fournit explicitement `S`, `O`, `Sn` et `T` à
`MqttControlBuilder`, avant `publishDevice`.

**Écart vérifié :** la préparation de l'enveloppe/du suivi de
séquence n'emprunte pas les mêmes appels.
**Non établi :** les valeurs produites diffèrent effectivement
dans la forme binaire nécessaire pour la C9C. Les noms `S/O/Sn`
et le seul ACK MQTT ne suffisent pas à conclure à un bug.

## 4. Décision de développement

**Ne pas remplacer le protocole par Jarvis et ne pas fabriquer un MSID.**
Les résultats beta22 prouvent le réveil `DP149=true`,
la publication de l'offre et son PUBACK broker, **pas** son acceptation
par la caméra. La réponse SDP de la même session reste absente.

**Prochaine étape statique prioritaire :** analyser
`Lcom/thingclips/sdk/mqtt/bqbppdq;->publishDevice` et les codecs
`bddqqbb`/`bqqppqq`, ainsi que la gestion `SandRMap/SandO`
dans `classes6.dex`. Comparer sur des **messages synthétiques**
la structure binaire du SDK à la fonction Python `_signal_frame`.
Ne publier une correction C9C-only que si l'écart est démontré,
avec des tests de non-régression C5L/H1L. Ne pas publier de fichiers DEX,
de codes propriétaires, de mots de passe, d'UID ou d'identifiants.

La version installable reste **0.8.13-beta25**. Aucun test caméra
ni mise à jour utilisateur nécessaire pour ce rapport.
