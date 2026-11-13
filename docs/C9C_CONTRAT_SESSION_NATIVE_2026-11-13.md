# C9C autonome — contrat de session native, preuves et seuil de développement

**13 novembre 2026 — complément hors ligne à l'audit 0.8.13-beta43**  
**Périmètre :** C9C autonome (sans station H1L) sur installation extérieure.  
**Méthode :** inspection du code GitHub et des classes DEX de l'APK AOSU 5.10.12 fournie par son propriétaire. Aucune opération sur les caméras, aucun compte ou secret interrogé.

## 1. Point de départ figé

- Branche principale `main` : `ffd0991428df4db169940ee7dde23e56cb92683e` ; manifest `0.8.13-beta43`.
- APK complète : SHA-256 `ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7`, 17 DEX, bibliothèques Android ARM64 Thing.
- Les trois caméras du banc historique (C5L + 2 × C9C3CA11/H1L) avaient vidéo et PTZ opérationnels en 0.8.10 : ne pas modifier leurs chemins.
- C9C autonome : aucune image vidéo ni réponse SDP à **notre propre session HA** n'a été validée.
- Historique bêta12 : pendant le direct **officiel AOSU**, 18/18 messages MQTT PV2.2 déchiffrés, dont des `answer` et `candidate` 302 avec SDP AES/KCP. Preuve de signalisation de la session officielle, pas de réussite de notre client.

## 2. Parcours Android étayé par les DEX

### Identité avant création de l'objet caméra

Dans `classes16.dex`, `TyCameraCenter.Oooo000` invoque `IotPlatform.Ty.getDevice().Oooo000(String)` puis transmet la **valeur retournée** à `ThingIPCSdk.getCameraInstance().createCameraP2P(String)`. Le pont `TyDeviceCenter.Oooo000` est associé au `GzDeviceInfo.cpDeviceId` du cache enrichi AOSU/Tuya.

**Limite :** ce schéma statique ne révèle pas la valeur que le SDK renvoie pendant le direct de la C9C. Le `devId` Tuya découvert dans l'inventaire ne doit pas être substitué au `cpDeviceId` par hypothèse. Les messages déchiffrés de la bêta12 renforcent le rapprochement opérationnel, sans liaison formelle SN ↔ devId.

### La connexion est une opération à états et callbacks

Dans `classes16.dex`, `TyCameraCenter$connectP2p$3$1.OooO0o0` consulte `IThingSmartCameraP2P.isConnecting` et appelle `IThingSmartCameraP2P.connect` avec callback. D'autres chemins réutilisent `TyP2pConnectCachePool` et la gestion de réveil ; **leur exécution précise pour cette C9C n'est pas établie**.

Dans `classes6.dex`, `ThingSmartCameraP2PSync.innerConnect` :
- accède à `IThingIPCDevice.getDeviceBean` ;
- sollicite `requestCameraConfig` ; ce dernier utilise `CameraBusiness.requestCameraInfo` ;
- lit `DeviceBean.getSkills`, `getDeviceP2PType` et l'état local du périphérique ;
- prépare le parcours adapté avant la création/gestion de session native.

La documentation Tuya décrit l'ordre logique `createCameraP2P → connect (callback) → startPreview (callback)`. Les exportations du binaire natif (préconnexion, connexion v2/v3, callbacks d'état) démontrent des composants possibles du moteur, **pas** que la préconnexion soit obligatoirement invoquée pour chaque C9C.

### Routage de signalisation

`ThingP2PSDK.sendMessageThroughMqtt` délègue à `P2PMQTTServiceManager.send302MessageThroughMqtt`. Selon le booléen de routage, Java utilise soit `lan302Publish` (via contrôle LAN Tuya), soit `IThingHomeCamera.publish` (avec `DeviceBean.getPv`, `getLocalKey`, compteur/sujet et callback). La branche effectivement utilisée lors du direct officiel **n'est pas prouvée** par la seule présence des deux implémentations.

Le codec 2.2 côté APK utilise `PublishBean2_2` (`data`, `protocol`, `t`), Fastjson, AES et CRC32. L'enveloppe Python est **structurellement** compatible ; pas de vecteur d'émission officiel bit-à-bit. Ne pas modifier l'AES/CRC par tâtonnement.

## 3. Écart avec notre client Home Assistant

| Phase | SDK officiel AOSU/Thing | Notre code actuel | Niveau de décision |
| --- | --- | --- | --- |
| Identité | jointure via cache `GzDeviceInfo` et `IotDevice` | sélection Tuya typée avec verrou si correspondance seulement heuristique | **Reste à démontrer sur le compte externe** |
| Capacités | `DeviceBean` / `skills` / fournisseur / état local | `p2p_skill=1635` et `security_level=3` insérés dans l'offre Python | **Valeurs natives effectives inconnues** |
| Configuration | `CameraBusiness.requestCameraInfo`, politique et session | RTC HTTP, `p2pConfig`, SDP AES/KCP assemblé | Structures proches, pas de parité de session |
| Établissement | `createCameraP2P` / `connect` / callbacks d'état | `sigQry(22)` puis `offer(302)` MQTT direct | **Machine d'états native manquante** |
| Signalisation | route LAN/MQTT choisie par le SDK | MQTT seulement, broker/sujet en dur | Transport effectif à confirmer |
| Succès session | callback P2P puis démarrage aperçu | PUBACK broker puis attente de SDP | PUBACK ≠ acceptation par l'IPC |
| Média | vidéo après connexion | aucun answer propre à HA sur C9C autonome | Impossible de valider le codec avant answer |

**Conclusion :** la correction doit viser la parité de la **création de session native** et de l'identité/du routage, pas ajouter une bêta diagnostique de champs ni changer les constantes au hasard.

## 4. Contrat minimal avant toute nouvelle tentative réelle

1. **Cible vérifiable** : conserver la barrière de `select_tuya_standalone_target_typed` ; aucune offre active vers un appareil sélectionné par unicité seule.
2. **Contexte de connexion non fictif** : reproduire ou démontrer l'équivalence des valeurs de capacités, version PV, session/politique et destination utilisées par le SDK, avec provenance de chaque champ.
3. **États explicites** : distinguer configuration, demande de connexion, signal envoyé, réponse de session, connexion confirmée, aperçu démarré, arrêt/nettoyage. Ne jamais traiter un PUBACK comme connexion.
4. **Routage démontré** : isoler la stratégie C9C autonome et justifier MQTT ou LAN ; aucun changement des chemins C5L/H1L.
5. **Preuve reproductible** : vérification hors ligne et tests à données synthétiques ; identifier l'écart précis avec la pile AOSU avant changement de comportement.
6. **Validation matérielle unique et ciblée**, uniquement si les cinq conditions précédentes sont remplies. Aucun PTZ C9C autonome avant confirmation vidéo et STOP.

## 5. Ce qu'il faut faire maintenant, sans nouveau test utilisateur

- Poursuivre le traçage statique du callback de `CameraBusiness.requestCameraInfo` vers la construction de session et les arguments natifs ; les symboles exportés seuls ne suffisent pas.
- Vérifier le contrat exact du booléen LAN/MQTT et du contexte `DeviceBean` dans les chemins de type P2P `4`, sans conclure du seul nom des méthodes.
- Formaliser les champs indispensables et les transitions à reproduire dans un module C9C séparé **seulement après vérification de leur sémantique**.
- Ne pas invoquer `thing.m.rtc.session.init` sans preuve qu'AOSU l'utilise pour cette caméra ; une présence DEX n'est pas une preuve d'appel.
- Si la pile Android propriétaire est indispensable sans voie autorisée portable, documenter explicitement cette limite plutôt que promettre une vidéo fonctionnelle.

## 6. Sécurité et non-régression

Ce document est public mais ne contient aucun binaire, identifiant, compte, image privée, clé locale, IP, MAC, SN, token, SDP ou PCAP. Toute recherche ultérieure se fait sur branche dédiée. Ne pas modifier `main`, `camera.py`, les services PTZ et les cartes des trois caméras existantes dans cette phase.

**Références internes :** `docs/C9C_PV22_CODEC_AND_NATIVE_SESSION_GAP_2026-11-13.md`, `docs/C9C_NATIVE_THING4_SIGNAL_ROUTING_AUDIT_2026-11-13.md`, `docs/C9C_TY_SDK_BRIDGE_STATIC_AUDIT_2026-11-13.md`, `custom_components/smart_aosu_cloud/tuya_mqtt_offer.py`, `tuya_rtc_inventory.py`.

**Référence externe officielle :** https://developer.tuya.com/en/docs/app-development/ipc-key-sample-live?id=Kdmyzhvgvfjmu

## 7. Vérification DEX : deux surcharges RTC distinctes

Une nouvelle lecture directe de `classes6.dex` confirme que les méthodes suivantes ont des **prototypes distincts** :

| Méthode (index DEX) | Paramètres Java résumés | Action interne |
| --- | --- | --- |
| `CameraBusiness.requestCameraInfo` (#4281) | `String, ResultListener` | `thing.m.rtc.session.init` |
| `CameraBusiness.requestCameraInfo` (#4282) | `String, Object, ResultListener` | `thing.m.rtc.config.get` |
| `CameraBusiness.requestCameraSessionInit` (#4283) | `String, Object, ResultListener` | `thing.m.rtc.session.init` |

**Preuve de liaison :** `ThingSmartCameraP2PSync.requestCameraConfig` (#5947) invoque la **surcharge #4282** ; `ThingSmartCameraP2PSync.innerConnect` (#5914) invoque `requestCameraConfig`. Dans cette chaîne visible, la configuration passe donc par `config.get`, **pas** par `session.init`.

Les autres surcharges existent dans le SDK, mais aucun chemin d'exécution propre à la C9C ne prouve que `session.init` soit requis. Ne pas injecter cet appel sur la seule base de sa présence dans les DEX. Les index sont propres à ce build 5.10.12.

## 8. Trace de la configuration **avant** le connecteur natif

Examen direct du corps de `ThingSmartCameraP2PSync.processCameraInfo` (méthode DEX #5931, `classes6.dex`). Cette méthode prépare un `ConfigCameraBean` à partir de la fiche `CameraInfoBean`, puis appelle `createDeviceIPC` (#5884). `createDeviceIPC` invoque `ICameraP2P.createDevice` avec callback.

Les références de méthode observées dans `processCameraInfo` comprennent :
- `getP2pSpecifiedType → setP2pType` ;
- `getId → setP2pId` pour un chemin de configuration ;
- `getP2PConfigStr → setToken` ;
- `getSkill → setSkill` ;
- `DeviceBean.getLocalKey → setLocalKey` ;
- `CameraInfoBean.getPassword` et `MD5Utils.md5AsBase64` avant `setPassword` dans le même corps ;
- `setDevId`, `setClientTraceId`, `setConfigJson` et, selon le chemin, informations produit/segmentation vidéo.

En amont, `innerConnect` (#5914) accède à `getP2pPolicy`, `getSessionTid` et `getClientTid` avant d'appeler `processCameraInfo`. `getClientTid` (#5900) construit une valeur locale à partir notamment de l'heure courante. **Le chemin exact emprunté pour la caméra C9C précise n'a pas été tracé à l'exécution** : il faut distinguer les références statiques des valeurs effectivement utilisées.

### Écart de données immédiatement vérifiable côté Python

`PrivateMediaBootstrap` dans `tuya_media_bootstrap.py` conserve des champs extraits du RTC (session, AES, ICE, TCP, localKey, SDP) et un `device_password` ; **il ne construit pas le `ConfigCameraBean` de Thing** ni son contexte complet. `tuya_mqtt_offer._media_payload` ne consomme pas `device_password` et fixe `p2p_skill=1635` ainsi que `security_level=3` sans preuve de leur équivalence avec `CameraInfoBean.getSkill` et la politique native.

Il existe donc un **écart concret de contrat d'initialisation**, indépendamment de la possibilité de déchiffrer le protocole MQTT 2.2. Ce n'est pas une preuve qu'un champ particulier, ajouté à l'offre Python, suffira à faire fonctionner la vidéo.

**Prochaine vérification hors ligne prioritaire :** identifier les conditions de branchement dans `processCameraInfo` pour le P2P type 4 et la façon dont `ConfigCameraBean` est transmis au moteur P2P ; seulement ensuite décider si une adaptation Python portable est réalisable. Aucune nouvelle offre, ni changement de `main`, n'est justifié pour le moment.

## 9. Trace Java complète : initialisation native → configuration → connexion → aperçu

Vérification hors ligne supplémentaire des références de méthodes dans `classes6.dex` de l'APK 5.10.12 exacte :

1. `ThingSmartCameraP2PSync.processCameraInfo` (#5931) appelle `createDeviceIPC` (#5884), lequel invoque `ICameraP2P.createDevice`.
2. L'implémentation `IPCThingP2PCamera.createDevice` (#4003) appelle **`initNativeOnce`** (#4030) puis `ThingCamera.createCamera`. La méthode `initNativeOnce` appelle explicitement **`ThingIPCSdk.getP2P().init`** et **`ThingCameraEngine.initP2PModule`**.
3. `IPCThingP2PCamera.connect` (#3998) lit `ConfigCameraBean.getPassword`, `getLocalKey`, `getP2pType`, `isLan`, `getInitString`, `getClientTraceId`, `getToken` et `getSkill`. Il transmet `getConfigJson` à **`ThingCameraInterface.setCameraConfig`**, puis appelle **`ThingCameraInterface.connect`** avec les mécanismes de callbacks et les branches SDK associées.
4. `IPCThingP2PCamera.startPreview` (#4099) vérifie notamment les états `isConnecting` / `isCameraCreated` puis invoque `ThingCameraInterface.startPreview`.

**Écart de conception désormais très précisément localisé :** notre `tuya_mqtt_offer.py` sait publier des messages MQTT, mais ne crée ni l'équivalent de `ThingCamera`, ni la configuration complète `ConfigCameraBean`, ni la machine de connexion native équivalente à `ThingCameraInterface.setCameraConfig/connect`. Une publication acceptée par le broker ne remplace aucun de ces états.

La chaîne de références est statiquement prouvée pour le **SDK embarqué**, mais le sous-chemin exact activé par la C9C extérieure (choix LAN/MQTT, type, préconnexion effective, arguments binaires) reste inconnu ; ne pas le déclarer confirmé matériellement.

### Décision de développement mise à jour

La prochaine intervention de code valable doit être **une étude de portabilité de la phase `setCameraConfig → connect`, limitée à C9C autonome**. Si son comportement dépend de routines ARM64 Android propriétaires non réimplémentables de manière légitime et fiable sur HA OS x86-64, il faudra constater cette limite ; ne pas transposer artificiellement la signature Java en paramètres MQTT sans preuve.

**Aucun changement de caméra, de configuration utilisateur, de service PTZ ni de `main` n'a été réalisé.**

## 10. NOUVEAU — branche Thing/P2P type 4 vérifiée sur les instructions DEX réelles

Audit indépendant hors ligne de l'APK originale AOSU 5.10.12, empreinte SHA-256 vérifiée. Cette section complète et affine les sections 8 et 9 ; il ne s'agit **pas** d'une connexion réelle à la C9C.

### Bifurcation vérifiée dans `processCameraInfo` (#5931)

La méthode occupe 14 registres, dont 6 registres d'arguments ; **`v11` désigne bien le troisième argument, `CameraInfoBean`**. Le sélecteur lit `getP2pSpecifiedType` en `v5`.

- À l'instruction 133, `const/4 v6, #4`. L'instruction 134 compare `v5` et `v6` (`if-ne`) et saute au type suivant lorsque le type n'est pas 4.
- **Pour le type 4**, les instructions 136–160 réalisent `CameraInfoBean.getId → ConfigCameraBean.setP2pId`, `getP2PConfigStr → setToken`, `getSkill → setSkill`.
- À l'instruction 164 commence une autre bifurcation (`const/4 v6, #2`). **Pour le type 2**, le SDK accède à `CameraInfoBean.getP2pId` puis à `getP2PConfigInitStr` et `getP2PConfigKeyStr` ; il ne s'agit pas du chemin type 4.

**Conséquence nouvelle :** il y a *deux espaces d'identification et deux étapes* à distinguer :

1. Côté **AOSU → SDK**, l'adaptateur `IotDevice.Oooo000` permet d'appeler `createCameraP2P` (pont `cpDeviceId` encore non prouvé à l'exécution sur cette C9C).
2. Côté **configuration RTC / P2P-4**, `ConfigCameraBean.p2pId` reçoit **`CameraInfoBean.id`**, et non `CameraInfoBean.p2pId`. Dans les réponses RTC de la bêta40, cet `id` était identique au `devId` Tuya **du candidat interrogé**, sans preuve définitive de son identité AOSU.

Ainsi, l'absence de `p2pId` dans un RTC de type 4 **n'est pas une raison suffisante de déclarer la réponse inutilisable**.

### Transmission du `CameraInfoBean` complet au moteur

Après préparation des champs, la méthode `processCameraInfo` effectue un `JSON.toJSONString(v11)` (instruction 308), où `v11` est l'objet **CameraInfoBean entier**. Le résultat `v9` est transmis à `ConfigCameraBean.setConfigJson` (instruction 312).

Dans `IPCThingP2PCamera.connect` (#3998), `ConfigCameraBean.getConfigJson` (instruction 263) est transmis à `ThingCameraInterface.setCameraConfig` (279) **si non vide**, avant un appel à l'une des trois surcharges de `ThingCameraInterface.connect` (302, 335 ou 360, selon les conditions).

La séquence locale `initNativeOnce → IThingP2P.init / initP2PModule` ainsi que `startPreview` ont aussi été vérifiées dans les méthodes concernées. Cela confirme un **contrat d'initialisation plus riche que notre seul payload MQTT**. L'appel `setCameraConfig` est conditionnel : ne pas écrire qu'il est impératif pour chaque type sans autre preuve.

### Réalisation reproductible et garanties

- Outil ajouté à cette branche : `tools/aosu_c9c_type4_route_offline.py`, limité au SHA exact de l'APK originale, qui affiche **8 indicateurs booléens de structure SDK** et aucun identifiant ni secret.
- Vérification locale sur l'APK réelle : **8/8 indicateurs vrais**.
- Tests synthétiques ajoutés : `tests/test_aosu_c9c_type4_route_offline.py` ; **6/6 réussis localement**.
- **Ne pas interpréter le 8/8 comme une vidéo opérationnelle** : il vérifie que les huit faits statiques examinés existent.
- Pas d'exécution du SDK, pas de caméra sollicitée, pas de MQTT ni de secrets renvoyés, pas d'APK ni de DEX ajouté à GitHub.

### Conséquence sur la stratégie de développement

L'obstacle restant n'est **pas** résolu par l'injection arbitraire de `CameraInfoBean.id`, de `p2p_skill` ou de `configJson` dans une offre MQTT. Il faut encore déterminer si l'initialisation/connexion Thing-4 est réimplémentable proprement et de façon portable, et sous quelles conditions la C9C utilise un routage LAN ou MQTT. Le SDK mobile Android et un SDK Linux **côté appareil** ne sont pas équivalents à un SDK Linux **côté client caméra**.

Pour la suite : conserver les trois caméras historiques intactes, comparer les arguments et états des trois surcharges `connect` sans secret ni émission réseau, puis décider explicitement de la faisabilité du client Home Assistant autonome. **Aucune nouvelle bêta installable ni test utilisateur ne sont justifiés à ce stade.**
