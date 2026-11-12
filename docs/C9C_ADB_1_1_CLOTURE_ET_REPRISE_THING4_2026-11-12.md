# Smart AOSU — clôture ADB P2P natif 1.1 et suite Thing-4
Date : 12 novembre 2026

## Rapport réel reçu — ADB sans root 1.1

Sur le téléphone où l'utilisateur a ouvert la C9C dans AOSU officiel :

- `etat = journal_application_visible_aucun_marqueur_p2p`
- `fenetre_temporelle_verifiable = true`
- `lignes_application_inspectees = 672`
- `lignes_logcat_horodatees = 4465`
- `lignes_entete_ignorees = 2`
- `lignes_anciennes_ignorees = 3793`
- `application_redemarree_pendant_test = false`
- `processus_application_interroges = 1`
- `logs_application_visibles_dans_fenetre = true`
- tous les marqueurs `createCameraP2P`, `innerConnect`,
  `DeviceBean`, `Thing P2P` et erreurs sélectionnées = 0 ;
- aucune commande caméra par l'outil, aucun journal brut conservé,
  aucun secret exposé.

**Conclusion stricte :** cette capture ADB est temporellement valide,
mais **ne donne aucune visibilité sur la création P2P native**.
L'absence de marqueurs ne prouve ni l'échec ni le succès du SDK
Android. Les compilations de production peuvent ne pas émettre ces
événements dans `logcat`.

**Décision : arrêt des scripts ADB et des sondes CP/UUID répétées.**
Pas de troisième essai logcat ou de nouvelle demande de capture sans
source de traces réellement différente et nécessaire.

## État technique conservé — Home Assistant 0.8.13-beta40

- C5L et 2 caméras C9C3CA11/H1L : vidéo et PTZ déjà confirmés
  sur l'installation de développement ; ne pas modifier leurs chemins.
- C9C autonome : `skills.p2pType = 4` côté Tuya,
  `p2pSpecifiedType = 4` sur deux API RTC, `CameraInfoBean.id`
  racine présent, identique au `devId` Tuya sélectionné ;
  `p2pConfig`, clé locale, `sessionTid`, `p2pPolicy`,
  `sessionId` présents.
- Le constructeur Python de SDP AES/KCP prépare une offre
  en RAM à partir des deux réponses RTC.
- Essais de signalisation précédents : connexion MQTT et PUBACK,
  mais pas de SDP answer démontrée sur C9C autonome.
- Correspondance **AOSU SN C9C ↔ Tuya devId non prouvée** ;
  l'unicité dans un compte ne démontre pas une identité.
- La bêta40 bloque les commandes C9C vidéo/réveil
  lorsque la cible Tuya n'est sélectionnée qu'heuristiquement.

## Ce que le SDK officiel prouve — et ne prouve pas

Le code `ThingSmartCameraP2PSync` présent dans l'APK AOSU
montre les références de `DeviceBean`, `skills`,
`CameraInfoBean`, `getP2PConfigStr`,
`createDeviceIPC` et `createCameraP2P`.
La branche `p2pSpecifiedType = 4` utilise
`CameraInfoBean.id` et la configuration P2P sérialisée.

Le SDK public Tuya décrit `createCameraP2P(devId)`,
`connect(devId)` et `startPreview`, avec
implémentations distinctes selon le fournisseur P2P.

**Attention :** une présence de méthode dans le DEX ou
un champ RTC complet ne prouve pas que cette méthode a
été exécutée pendant la session réelle de la C9C.
Aucune parité d'octets ni acceptation de session Thing-4
par notre Python n'a été démontrée.

## Audit complémentaire du projet Python indépendant

Source : `roquerodrigo/tuya-ipc-p2p-sdk`, MIT, alpha.

- L'implémentation Python décrit : API mobile,
  `m.ipc.v4.rtc.config.get`, signalisation MQTT
  binaire `2.2`, SDP `AES/KCP`, ICE,
  relais TCP/KCP, authentification et réassemblage JPEG.
- Elle signale explicitement des essais matériels validés
  principalement en région US avec médias MJPEG.
  Les appareils H.264 et les autres régions restent
  non démontrés dans la documentation de ce projet.
- Son `MotoClient` envoie `sigQry` puis une offre SDP,
  avec `from`, `to`, `sessionid`, `moto_id`, et gère
  `answer` / `candidate` / `disconnect`.
  La base Smart AOSU suit ce **même type de signalisation**.
- Cela ne permet **pas** de conclure que ce protocole
  est la voie réelle employée par la C9C AOSU Thing-4.
- Le projet public désactive la vérification TLS du
  broker dans une de ses implémentations. **Ne pas
  adopter ce relâchement** dans Smart AOSU : TLS
  vérifié fonctionne déjà chez l'utilisateur.

## Recherche prioritaire — sans nouveau test utilisateur

1. Isoler la **preuve de cible** AOSU SN ↔ Tuya devId
   issue de données autorisées, sans inférence à partir
   de la seule présence d'un périphérique Tuya.
2. Comparer la **création de session native Thing-4**
   aux constructions de session et de signalisation
   disponibles dans notre Python, particulièrement
   les prérequis non reproduits (DeviceBean,
   configuration Fastjson, initialisation du transport).
3. Éviter de confondre **SDK mobile client Android**
   et **SDK Linux embarqué côté caméra** ; le second
   ne peut pas automatiquement servir de lecteur
   vidéo Home Assistant.
4. Conserver deux niveaux de preuves :
   a) compatibilité structurelle des données Tuya,
   b) preuve de bout en bout d'une session caméra.
   Le premier n'implique jamais le second.
5. Ne relancer **qu'un seul essai physique ciblé**
   après un correctif démontré hors ligne
   et un contrôle d'identité suffisamment solide.
   Pas d'offre MQTT sur simple sélection heuristique.
6. Conserver `0.8.13-beta40` en attendant :
   pas de bêta41 de diagnostic superficiel.

## Critères de sortie

- **Identité :** cible C9C autonome certifiée par
  association explicite AOSU/Tuya, sans nom d'appareil,
  ordre de liste ou hypothèse d'unicité.
- **Protocoles :** comparaison documentée et testée
  du chemin fournisseur Thing-4, puis du format SDP
  et des messages de signalisation. Aucun code OEM
  ni secret inséré dans GitHub.
- **Robustesse :** aucun changement des vidéos,
  PTZ et entités C5L/H1L validées.
- **Essai physique :** consentement manuel explicite,
  limitation à un essai et résultat anonymisé utile.

## Références

- Tuya IPC SDK Android, création, connexion, preview :
  https://developer.tuya.com/en/docs/app-development/livestream?id=Ka6nuvynnjk7h
- Tuya P2P channel SDK Android :
  https://developer.tuya.com/en/docs/app-development/android-p2p?id=Kalemnh8lf8yi
- Tuya Embedded SDK P2P **côté appareil**, distinct du client :
  https://docs.tuyaopen.ai/docs/tuyaopen-core/p2p-api
- SDK Python indépendant MIT (alpha) :
  https://github.com/roquerodrigo/tuya-ipc-p2p-sdk

Aucun compte, clé, numéro de série, IP, donnée personnelle,
APK OEM ou contenu de `logcat` n'est enregistré dans
ce document public.
