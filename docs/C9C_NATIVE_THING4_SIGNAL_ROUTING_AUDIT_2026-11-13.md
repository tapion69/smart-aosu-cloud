# C9C autonome — chemin MQTT/LAN natif réellement utilisé par AOSU

**13 novembre 2026 — audit technique complémentaire, aucune bêta Home Assistant**

## Décision de développement

Conserver **0.8.13-beta43**. Aucun bouton ni essai utilisateur supplémentaire.
Ne plus faire dépendre toute la recherche de `cpUuid` : les réponses
cloud ont été épuisées, et les observations de signalisation officielle
de la bêta12 sont plus fortes que la simple unicité de l'inventaire Tuya.

### Preuve historique majeure retrouvée

Pendant l'ouverture du direct de la C9C dans **l'application officielle**,
l'observateur passif Smart AOSU avait déchiffré **18 messages P2P 2.2
sur 18**. Parmi eux, les événements de protocole 302 incluaient
une **SDP answer AES/KCP** et des **candidats ICE**.

Dans les cinq événements 302 classés, le champ `from` correspondait
au périphérique Tuya sélectionné et `to` à l'UID du compte ; le champ
`path=mqtt` et `sessionid` étaient présents ; `moto_id`
n'était pas présent. Ces indicateurs ont été relevés lors du
direct réellement ouvert dans l'application. Ils constituent
**un rapprochement opérationnel important** de ce device Tuya
et de la vidéo AOSU, mais ne forment pas une preuve formelle
du même numéro de série AOSU (ni une validation du moteur HA).

La bêta16 a pu s'abonner au sujet sortant MQTT, mais n'y a
pas observé l'offre officielle. **Il n'existe donc pas de capture
native de l'offre à comparer octet par octet**.

Les essais de notre propre offre ont reçu un PUBACK du broker,
mais **aucune réponse SDP correspondant à la session HA**.
Cela resserre le problème sur la création de session / émission
de la signalisation et/ou le ciblage.

## Nouvelle reconstitution JNI → Java → services Tuya

APK analysée **localement**, archive AOSU 5.10.12 complète
(SHA-256 documenté dans le dépôt). Les fichiers binaires
ne sont pas copiés dans GitHub.

### 1. La bibliothèque P2P native délègue l'envoi au Java

La bibliothèque ARM64 `libThingP2PSDK.so` exporte
`ThingSmartP2PSDK::SendMessageThroughMQTT`,
`ThingSmartP2PSDK::SendMessageThroughLAN`,
`ThingP2PSetSignaling`, `ThingP2PSetHttpResult`
et `ThingP2PConnect_v3`.

Le désassemblage de `SendMessageThroughMQTT` montre
un appel JNI `CallStaticVoidMethod`. Dans `classes6.dex`,
`ThingP2PSDK.sendMessageThroughMqtt(boolean, String, String)`
délègue à
`P2PMQTTServiceManager.newInstance().send302MessageThroughMqtt`.

**Ce n'est donc pas un simple SDK natif qui publierait
directement sur notre socket MQTT Python.** La couche Java
choisit le service applicatif et les paramètres du message.

### 2. Une branche LAN et une branche MQTT, commandées par un booléen

Sur la méthode Java `send302MessageThroughMqtt` :

- Signature : `(boolean isByLan, String deviceId, String data)`
  selon le type des registres (nom descriptif donné au booléen
  par la chaîne de journalisation `is by lan`).
- Son code DEX comporte exactement **75 unités**.
- Le booléen est présent dans `v8`. L'instruction
  `if-eqz v8` à l'unité 44 saute à l'unité 55 si faux.
- Si le booléen est **vrai**, la méthode appelle
  `IThingHomeCamera.lan302Publish`, puis retourne.
  L'implémentation Java `lan302Publish` transmet à
  `IThingDeviceListManager.lanControl`.
- Si le booléen est **faux**, elle appelle
  `DeviceBean.getPv` et `DeviceBean.getLocalKey`,
  puis `IThingHomeCamera.publish` avec le protocole
  302, la fiche d'appareil et un callback de résultat.

Les deux chemins consultent la fiche de l'appareil
et effectuent un suivi des messages `isP2PFirstMqttStart`
et `p2pMqttSendCount`.

**Attention :** ce code prouve l'existence des deux routes,
mais pas laquelle était choisie pour la C9C pendant son
direct officiel.

### 3. La couche Java MQTT construit une véritable trame 2.2

Dans `classes6.dex`, l'implémentation
`IThingHomeCamera.publish` est dans une classe obfusquée.
Elle réutilise `SandO`/`SandRMap` et renseigne un
`MqttControlBuilder` avec `data`, `localKey`,
`pv`, `protocol`, `topicId`, `sn`, `O`, `S`, `t`.
Puis elle appelle `IMqttServer.publishDevice`.

Cela **confirme la famille de message** déjà étudiée
dans les bêtas 25-26 : la version P2P, la clé locale,
les compteurs et l'identifiant de topic ont un rôle
explicite dans le message natif. Les vecteurs Python
2.2/AES/CRC conformes au SDK Python MIT sont utiles,
mais il n'existe toujours **aucun vecteur byte-à-byte
issu de l'application AOSU officielle**.

## Écart avec Smart AOSU Python (bêta43)

| Dimension | Java / natif AOSU | Python actuel |
| --- | --- | --- |
| Objet caméra | `IThingIPCCore.createCameraP2P`, `ThingP2PConnect` | Aucun équivalent natif valide |
| Direction du signal | booléen `isByLan` : `lan302Publish` ou `publish` | Publication MQTT uniquement |
| Version de protocole | `DeviceBean.getPv` | Enveloppe codée `2.2` |
| Clé du message | `DeviceBean.getLocalKey` | `localKey` obtenue via inventaire Tuya |
| Séquence | `SandO`, `SandRMap`, callbacks | Compteur/source imités dans la bêta26 |
| Routage | Service Tuya `IThingHomeCamera` | `smart/mb/out/{deviceId}` codé en dur |
| Contexte session | `DeviceBean`, politique, `sessionTid`, état SDK, choix LAN | SDP local + trame 302, pas de machine native |
| Résultat C9C autonome | Officiel : answer + ICE observés | HA : PUBACK seulement, pas d'answer |

Le simple succès de la publication MQTT ne prouve pas le bon
`pv`, la bonne destination, l'initialisation native, ou
la livraison de l'offre à la C9C.

## Ce que cette recherche ne permet pas d'affirmer

- Le mode LAN n'est pas prouvé actif pour cette C9C.
- L'absence d'un `cpUuid` dans les HTTP AOSU n'invalide
  pas l'identifiant utilisé dans le cache SDK Android.
- Le fait que les messages officiels aient été déchiffrés
  avec la clé de l'appareil sélectionné renforce le
  rapprochement, **pas** la preuve d'identité par SN.
- Les symboles/branches du SDK ne sont pas une capture
  du paquet ou des arguments natifs exécutés.
- Les bibliothèques de l'APK sont Android/ARM64 :
  elles ne sont pas directement chargeables dans
  l'installation Home Assistant OS x86-64.

## Prochain travail réellement utile

1. **Conserver le verrou d'envoi vers une cible purement
   heuristique**, mais ne plus traiter cette cible comme
   un simple appareil Tuya sans preuve d'activité :
   la bêta12 a fourni un signal officiel fort.
2. Comparer la logique `MqttControlBuilder` /
   `IMqttServer.publishDevice` à notre encodeur 2.2
   et établir les écarts structurels **sur l'APK déjà fournie**.
   Contrôler le rôle de `pv`, les identifiants de topic,
   les compteurs `S/O`, les callbacks d'envoi,
   le `sessionid` et les méthodes LAN.
3. Séparer les **faits observés sur la C9C** de la
   **structure statique** dans une matrice d'état.
4. Si l'absence de SDP s'explique par un écart précis,
   faire un correctif **exclusivement C9C autonome**
   sur une branche expérimentale avec tests de non-régression.
   Ne pas créer une bêta pour des champs supplémentaires.
5. En l'absence de parité native démontrable sans SDK
   propriétaire Android, déclarer honnêtement la limite.

## Documentation et alternatives — attention aux coûts

La documentation du SDK Android Tuya décrit les phases
`createCameraP2P`, `connect`, puis `startPreview` :
https://developer.tuya.com/en/docs/app-development/livestream?id=Ka6nuvynnjk7h

Tuya propose par ailleurs des API cloud de vidéo
RTSP/HLS et WebRTC mais certaines nécessitent
l'activation d'un service facturé. Ces API ne sont
**pas une solution démontrée** pour la C9C AOSU solaire,
ni un substitut gratuit/local :
https://developer.tuya.com/en/docs/iot/iot-video-live-stream?id=Kaiuyzn1xn2aa

L'éditeur AOSU indique ne pas proposer ONVIF/RTSP
pour ses caméras sur batterie (déclaration publique
du 28 janvier 2026) :
https://community.aosulife.com/t/2k-wi-fi-camera-home-assistant-integration/5826/5

### État du dépôt

- Nouveau script de vérification statique reproductible :
  `tools/aosu_native_302_routing_offline.py`
- Tests synthétiques uniquement :
  `tests/test_aosu_native_302_routing_offline.py`
- **Aucune nouvelle bêta HA**, aucune vidéo envoyée,
  aucune modification des contrôleurs C5L / H1L.
- Aucun secret, numéro de série, APK ou bibliothèque
  propriétaire commis sur GitHub.
