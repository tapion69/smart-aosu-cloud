# Smart AOSU Cloud — audit croisé des deux APK, du SDK natif et du chemin C9C

**Date : 10 novembre 2026.** État Home Assistant : **0.8.13-beta32**, inchangé. Analyse locale et hors réseau des deux fichiers fournis, avec le code du dépôt et les résultats beta22–beta32. Aucun APK, DEX, .so, secret, numéro de série, identifiant Tuya ou capture privée publié.

## 1. Sources vérifiées

| | APK complet AOSU 5.10.12 | APK Lite de diagnostic |
|---|---|---|
| SHA256 archive | `ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7` | `6a3692aa0dc2385f9d988ffbcf7a703249d426b022f78857d2b380748e790be1` |
| Code DEX | **17 DEX** | **un seul DEX**, `classes11.dex` |
| Bibliothèques ARM64 | **75 .so** | **une seule .so**, `libglazero-security.so` |
| Manifeste Android dans base.apk | Oui | Non |
| Bibliothèques caméra/RTC Tuya | Présentes | Absentes |

`classes11.dex` et `libglazero-security.so` de l'APK Lite sont chacun **identiques octet pour octet** aux composants correspondants de l'APK complet. Le Lite est une extraction incomplète, **pas** une version fonctionnellement équivalente. Les diagnostics négatifs réalisés avec le Lite ne pouvaient pas invalider la présence d'un protocole caméra dans les 16 autres DEX ou les bibliothèques natives.

Le complet a exactement l'empreinte de la précédente archive analysée ; il ne s'agit pas d'une version logicielle différente.

## 2. Parcours vidéo officiel démontré dans le bytecode

- `classes11.dex` : `UUIDInfoWebDataItem.coopUUID` peut être converti en `GzDeviceInfo.cpDeviceId`.
- `classes15.dex` : `DeviceInfoRepoImpl` et `TyDeviceInfoSource` réalisent des rapprochements/cache d'appareils AOSU et Tuya.
- `classes16.dex` : `TyCameraCenter.Oooo000` appelle `ThingIPCSdk.getCameraInstance()` puis `IThingIPCCore.createCameraP2P()`.
- `classes6.dex` : `CameraConstant.getSdkProvider` consulte `DeviceBean.skills`, `ProductBean.category` et l'état de l'appareil. `ThingSmartCameraP2PSync.innerConnect` utilise `getDeviceP2PType`, `getIPCConfigInfo`, `getP2pPolicy`, `getSessionTid`, `getClientTid`, des informations de connexion locale et le traitement de la configuration caméra.
- Split ARM64 : `libThingP2PSDK.so` expose des fonctions de connexion P2P `connectV2/connectV3`, de signalisation `setSignaling` / `SendMessageThroughMQTT`, d'autorisation et d'initialisation RTC ; `libThingCameraSDK.so` contient également des composants PPCS. La présence de ces derniers ne démontre pas que **cette** C9C utilise PPCS.

Ces références sont des appels présents dans le code exécuté par le SDK, pas uniquement des noms de fichiers. En revanche, elles ne révèlent pas quelles valeurs privées sont effectivement utilisées par la C9C externe.

Documentation publique Tuya corroborante :
- https://developer.tuya.com/en/docs/app-development/ipc-key-sample-live?id=Kdmyzhvgvfjmu
- https://developer.tuya.com/en/docs/app-development/preparation?id=Ka8j28bt6i7eo

## 3. Divergence majeure avec le moteur expérimental Home Assistant

`tuya_media_bootstrap.py` construit un SDP AES/KCP de référence dans la RAM ; `tuya_mqtt_offer.py` crée une enveloppe JSON/AES/CRC maison et émet une requête `sigQry` en protocole 22 avant un message de protocole 302, via `smart/mb/out/<devId>`.

Le SDK officiel suit, lui, `createCameraP2P` puis la création/connexion native, avec la politique et les identifiants de session précités. **Le chemin Python n'est pas une reproduction démontrée du chemin Thing IPC.** Aucune des lectures RTC réussies ne valide cette parité.

### Origine de `sigQry` : indice oublié

Sur les 17 DEX, la chaîne exacte `sigQry` a été retrouvée dans **`classes4.dex`**, au sein d'un gestionnaire de réponses `MQ_203_DataReceivedBean` qui appelle **`WifiSignalListener.onSignalValueFind`**. Aucune occurrence de cette chaîne n'a été détectée en clair dans les bibliothèques natives P2P/caméra, et elle n'est pas présente dans les DEX du parcours caméra étudiés.

**Il n'existe donc aucune preuve dans cet APK que `sigQry` constitue une requête préalable nécessaire à une offre vidéo.** La traiter comme un élément confirmé du protocole caméra serait une erreur. Cela ne prouve pas non plus que le protocole 302 est invalide : ce point nécessite une comparaison des formats et du routage réels.

### Autres écarts à instruire hors réseau

1. Les données Tuya du test C9C externe n'ont **ni modèle, ni catégorie, ni ProductBean** ; le SDK officiel utilise pourtant ces éléments pour sélectionner son fournisseur/sa politique P2P.
2. `sessionTid`, `clientTid`, `p2pPolicy` et l'état local sont pris en compte par le SDK mais non reconstruits dans l'offre manuelle.
3. Le SDK initialise MQTT par `getMqttConfigInfo` et `Domain.mobileMqttsUrl` ; le Python fixe `m1.tuyaeu.com:8883`. Le broker accessible ne prouve pas la même configuration de session.
4. Le SDK emploie `MqttControlBuilder` et ses champs `S/O/Sn/T` puis un codec interne ; la parité binaire avec `_signal_frame` Python reste non prouvée, même après la correction des compteurs `SandO`.
5. Le SDK contient littéralement `thing.m.rtc.config.get`. La chaîne littérale `m.ipc.v4.rtc.config.get` n'a pas été trouvée dans les DEX examinés. Cela **n'exclut pas** une composition dynamique ou l'usage d'une autre version ; « API acceptée » n'est pas synonyme de « méthode native utilisée par la caméra ».

## 4. Recoupement des essais réels beta22 à beta32

- **C5L et deux C9C3CA11 sur H1L :** vidéo et PTZ fonctionnels, leurs chemins ne doivent pas changer.
- **C9C autonome externe :** DP149 réveillé dans les essais, publication MQTT et PUBACK broker confirmés, mais jamais de SDP de réponse ni de JPEG.
- **Beta29/30 :** candidat Tuya accessible ; SN/correspondance AOSU non prouvés ; `skills.p2pType=4` déclare Thing, mais catégorie et modèle absents.
- **Beta31 :** cinq lectures Tuya acceptées, modèle produit non demandé faute de version ; trois configurations RTC présentent des indices d'authentification, de moto_id, ICE, TURN et AES/KCP, mais aucun `msid` détecté. Ce sont des métadonnées, **pas** des sessions vidéo ouvertes.
- **Beta32 :** aucun `coopUUID`, `cpDeviceId` ni `cpDeviceInfo.cpDeviceId` exploitable dans l'enregistrement AOSU. Sélection du seul candidat Tuya **heuristique**, pas une identité exacte.
- **ADB Windows 1.2 :** téléphone, processus AOSU et logcat lus avec succès, mais aucun marqueur CP/cache détecté. Cela ne permet pas d'inférer une absence de CP dans les données privées de l'application.

## 5. Évaluation et prochaines étapes de développement

**Prouvé :** le Lite manque le moteur vidéo ; le SDK utilise une chaîne P2P native avec métadonnées de session et de politique absentes du parcours Python ; l'identité de la cible C9C n'est pas démontrée ; le PUBACK MQTT ne prouve pas l'arrivée de l'offre à la caméra.

**Hypothèse technique prioritaire :** la structure de session, la sélection du fournisseur caméra et/ou la signalisation native diffèrent de notre offre artisanale. C'est un meilleur axe d'audit que répéter les cinq requêtes Tuya déjà acceptées. La cause exclusive du blocage reste inconnue.

**Plan :**
1. Comparer **hors réseau** les exigences SDK `DeviceBean / ProductBean / skills / p2pPolicy / sessionTid / clientTid` à toutes les données réellement obtenables dans le backend, sous forme d'un seul tableau de couverture et sans exposer les valeurs.
2. Vérifier la parité **binaire sur messages synthétiques** entre le codec du SDK (MQTT `MqttControlBuilder`) et l'enveloppe Python, sans envoyer d'offre à la caméra.
3. Évaluer séparément (a) un pont Android utilisant un SDK officiellement autorisé et sous licence, et (b) un moteur Python indépendant fondé sur des spécifications ou des échanges effectivement vérifiés. **Ne pas redistribuer de bibliothèques propriétaires dans le dépôt public.**
4. Exiger une correspondance exacte de la caméra avant un nouveau test de commande. Un compte avec un seul périphérique Tuya ne suffit pas.
5. Une fois les deux conditions (identité, parité P2P) satisfaites, réaliser **un seul test matériel C9C autonome**, avec tests de non-régression C5L/H1L.

**Décision : pas de beta33 d'essais partiels et pas de nouvelles offres SDP actuellement.** Manifeste Home Assistant maintenu en `0.8.13-beta32`. Aucun changement des trois caméras fonctionnelles.

Ce rapport ne contient que des références de méthodes publiques, des indicateurs de présence et les résultats anonymisés déjà connus. Les deux APK et les bibliothèques ne sont pas publiés.
