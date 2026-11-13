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
