# Smart AOSU Cloud — audit statique MQTT de l'APK AOSU 5.10.12 complet

**8 novembre 2026.** Ce document conserve les constats hors réseau effectués après le diagnostic beta25 sur l'APK Lite.

## Source vérifiée

L'APK original AOSU 5.10.12 fourni précédemment a été retrouvé et vérifié : 200 265 946 octets, SHA-256 conforme à l'empreinte attendue par l'intégration. L'archive contient un `base.apk` de 232 903 121 octets décompressés avec **17 DEX**. Le diagnostic installé sous HA avait examiné l'APK Lite (1 690 990 octets et 1 DEX) : ses absences de marqueurs n'étaient pas concluantes.

L'analyse a été statique, locale et sans accès au compte ni aux caméras. Aucun APK ou actif propriétaire n'est ajouté au dépôt.

## Indices vérifiés dans les 17 DEX

| Indice | Observation |
|---|---|
| `/api/jarvis/mqtt`, `/api/jarvis/config`, `jarvis` | Pas de chaînes exactes dans les tables DEX |
| `/av/u/`, `/av/moto/` | Pas de chaînes exactes dans les tables DEX |
| `mobileMqttsUrl` | Présent dans `classes5.dex` |
| `getMqttConfigInfo` | Références dans `classes4.dex` et `classes5.dex` |
| `ThingMqttServerManager`, `MqttConfigBean` | Présents dans `classes5.dex` |
| `TyDeviceCenter$mqttServerStatusCallback$1` | Présent dans `classes16.dex` |
| `AWSIotMqttManager` | Présent dans `classes10.dex` (usage par C9C non établi) |
| `thing.m.rtc.config.get` | Présent dans `classes6.dex` |
| MSID de session WebRTC exploitable | Non démontré : `mSid`/chaînes proches ne constituent pas un `msid` confirmé |

### Références Java pertinentes

- `IThingGetBaseConfig.getMqttConfigInfo`
- `Domain.getMobileMqttsUrl`
- `ThingSmartNetWork.getMqttUrl`
- `ThingMqttPlugin.getMqttServerInstance`
- `IMqttServer` : abonnements, publications et statut
- `MqttConfigBean` : champs structurels clientId, userName, SSL key/password, QoS, keepAlive — **aucune valeur privée exportée**
- `TyDeviceCenter$mqttServerStatusCallback$1` : callbacks `onConnectSuccess` et `onConnectError`

## Portée et direction

La présence de ces classes démontre leur inclusion dans l'APK, **pas** qu'elles sont invoquées pour la C9C autonome. L'absence de littéraux Jarvis n'exclut pas une construction dynamique ou un appel natif. La présence de WebRTC déclarée par les réponses cloud beta23/24 ne prouve pas le transport vidéo effectif.

**Priorité suivante :** suivre les instructions DEX des classes ci-dessus pour établir l'origine effective de la configuration MQTT, du domaine, de l'authentification et du choix de session C9C. Comparer ensuite cette chaîne aux constats beta22 : réveil DP149=true, offre MQTT acquittée, aucune réponse SDP.

Aucun changement aux moteurs C5L/H1L, aucune modification de l'APK Lite et aucun nouvel essai d'offre vidéo avant vérification. La beta25 déjà publiée sait détecter l'APK original vérifié s'il est installé à côté de l'APK Lite, mais le présent audit a été effectué séparément et ne nécessite pas de nouvel envoi utilisateur.
