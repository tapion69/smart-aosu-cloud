# Smart AOSU Cloud — moteur d'états Thing-4 C9C autonome (14 novembre 2026)

**État : code expérimental et tests hors ligne, aucun direct validé sur la C9C autonome.**
Le projet `main` reste sur `0.8.13-beta44-rc3`. Les caméras historiques
(C5L et 2×C9C3CA11/H1L) ne sont pas modifiées.

## Pourquoi ne pas relancer l'offre cloud

Deux appels manuels `thing.m.rtc.session.offer_1.0` ont été **explicitement
rejetés** par le serveur Tuya. Les corrections de l'en-tête HTTP n'ont pas
changé ce résultat. L'APK d'AOSU 5.10.12 utilise `createCameraP2P`,
`setCameraConfig`, `connect` et ses callbacks, puis l'encodeur SDP natif
et des jetons issus de l'état de session. Notre ancien test n'instanciait
pas ce moteur de session.

**Ce que fait la nouvelle modification** : le module Python
`custom_components/smart_aosu_cloud/c9c_thing4_session_state.py` fournit
un modèle de session **portable, strict et réutilisable**, mais
**n'implémente pas encore** le transport réel. Il n'importe pas le
SDK Android et ne prépare pas de faux SDP.

## États de session distincts

`nouvelle → identite_verifiee → configuration_verifiee →
peripherique_p2p_cree → connexion_en_cours → offre_emise →
reponse_sdp_recue → connexion_p2p_confirmee → premiere_image_recue`.

Pour chaque étape :

1. **Identité** : seule une correspondance typée exacte établie à partir
   de l'AOSU et de Tuya est admise ; caméra C9C autonome unique sans H1L.
   Un `candidat_unique` ne suffit pas.
2. **Configuration** : `CameraInfoBean.id` doit être exactement le
   `devId` sélectionné, `p2pSpecifiedType=4`, clé locale et
   configuration RTC effectivement présentes, session récente
   (expiration à 90 secondes).
3. **Création périphérique** : succès **réel** de l'adaptateur P2P,
   et non simple présence de paramètres Android.
4. **Démarrage connexion et émission d'offre** : transitions explicites ;
   le module ne fait pas lui-même ces appels.
5. **PUBACK MQTT** : mémorisé comme transport broker seulement ;
   **ne prouve ni réception par la caméra, ni SDP answer, ni vidéo**.
6. **SDP answer** : doit être validée et liée exactement à **notre**
   identifiant de session et à la caméra Tuya autorisée.
7. **Connexion authentifiée** : callback de connexion P2P réel ;
   il peut arriver avant l'answer, mais les deux preuves sont
   requises pour atteindre `connexion_p2p_confirmee`.
8. **Première image** : seul un véritable paquet média décodé et
   accepté peut établir `premiere_image_recue`.

L'arrêt, l'expiration ou l'échec purgent les identifiants éphémères et
les marqueurs de confirmation. Aucun SN, devId, UID, SDP, clé ou secret
n'est retourné dans les statuts ou les exceptions.

## Tests

- `tests/test_c9c_thing4_session_state.py` : **17 tests hors ligne**,
  dont succès ordonné, callbacks inversés, messages en avance,
  mauvaise cible, mauvaise session, réponse non validée,
  `p2pSpecifiedType` différent de 4, clé absente, état expiré,
  `PUBACK` sans answer, absence de première image et nettoyage.
- Compilation Python de l'intégration + tests d'identité CP↔Tuya
  + suspension de l'ancien test HTTP, dans
  `.github/workflows/c9c-android-cp-devid.yml`.
- Tests GitHub :
  https://github.com/tapion69/smart-aosu-cloud/actions/runs/43593507613 .

Le module n'est pas branché à un moteur réseau : les tests **n'affirment
pas** que le moteur natif fonctionne chez le frère.

## Bloquants restants — sans nouvelle manipulation chez le frère

- **Identité** : le `cpDeviceId` AOSU authentique n'était pas présent
  dans les réponses HTTP du compte extérieur. L'APK officielle enrichit
  un cache privé Android, inaccessible via les providers non exportés.
  Les sources publiques/requêtes Tuya disponibles ne prouvent pas encore
  la liaison SN↔devId de cette caméra.
- **Adaptateur P2P** : il faut fournir une implémentation Python
  compatible avec la génération de SDP, les jetons, le routage
  LAN/MQTT/HTTP et les vrais callbacks `createDevice/connect`.
  Les bibliothèques AOSU ARM64/Android ne sont pas directement
  chargeables dans HA OS x86-64.
- **Codec** : une fois seulement la session vraiment connectée,
  valider le format vidéo de la C9C (le client Python Tuya public a été
  testé surtout avec des appareils MJPEG, pas cette caméra).
- **Nettoyage de sessions** : interdire les retries agressifs et
  fermer le transport avant tout nouvel essai pour éviter
  une caméra bloquée par une ancienne session.

## Conclusion de cette étape

La correction sur la branche n'ajoute aucun bouton, aucun appel Tuya,
aucune nouvelle version à installer ; elle met en place le **contrat
du futur adaptateur de connexion**, sans confondre acceptation HTTP,
broker MQTT et vidéo. La prochaine implémentation doit établir une
correspondance d'identité effective puis fournir un **vrai transport**.

PR draft : https://github.com/tapion69/smart-aosu-cloud/pull/4 .
