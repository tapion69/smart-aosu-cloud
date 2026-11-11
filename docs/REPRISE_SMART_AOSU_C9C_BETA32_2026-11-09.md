# Point de reprise — Smart AOSU Cloud / C9C autonome

Établi le 9 novembre 2026. Conservé pour faciliter la reprise d'une autre discussion.

## Dépôt et état installable

- GitHub : tapion69/smart-aosu-cloud, branche main.
- Dernière version installable : **0.8.13-beta32**.
- Les fichiers d'analyse APK précédents sont conservés sans installation HA.
- La beta32 corrige le pont d'identité CP de la C9C autonome, sans toucher aux moteurs vidéo.
- Matériel fonctionnel sur la première installation :
  **C5L autonome + deux C9C3CA11 associées à la station H1L**.
  Parcours caméra, contrôle PTZ et présentation Home Assistant déjà validés.
- Autre installation : **une C9C autonome appartenant au frère**,
  sans station H1L. La vidéo reste indisponible dans Smart AOSU,
  alors qu'elle fonctionne dans l'application AOSU.

## Bilan des principales étapes

- Beta22 : réveil de la C9C autonome DP149=true confirmé, l'offre
  vidéo est envoyée sur la même connexion MQTT et reçoit un PUBACK.
  Aucun SDP reçu. Un PUBACK n'est pas une confirmation caméra.
- Beta23 et beta24 : réponses IPC et RTC avec indices WebRTC,
  auth et moto_id, mais sans MSID explicite exploitable.
- Beta25 : APK allégé (1 DEX) insuffisant ; original AOSU 5.10.12
  (17 DEX) retrouvé et analysé localement. Signaux MQTT et
  appels Thingclips identifiés, sans dépendre des API Jarvis.
- Beta26 : compteurs SDK S/O appliqués à la C9C autonome,
  sans obtenir de nouvelle réponse SDP.
- Beta27/28 : fiches AOSU et Tuya ; SN AOSU vérifié dans la fiche AOSU,
  mais aucune liaison prouvée avec l'identifiant Tuya interrogé.
  Correction de la limite de reconnexion Fiche Tuya à 20 min.
- Beta29 : SN absent dans la fiche Tuya, référence AOSU
  indisponible, productId présent ; métadonnées modèle et
  catégorie insuffisantes.
- Beta30 : skills.p2pType = 4, classé Thing par le SDK.
  Cela ne prouve ni identité ni protocole vidéo réel.
- Beta31 : bouton Diagnostic complet, 5 lectures Tuya acceptées
  sur 6 possibles. Modèle produit non demandé car version absente.
  productId cohérent entre fiche et inventaire Tuya seulement ;
  produit sans catégorie/modèle/capacités reconnus ; IPC v2,
  RTC IPC-v4 et RTC classique acceptés. Les trois affichent
  WebRTC/auth/moto_id/ICE/TURN/session/AES-KCP, sans MSID.
  Identité AOSU/Tuya NON confirmée.

## Découverte dans l'APK complet

La chaîne SDK Android vérifiée, sans accès au compte ni caméra :

1. UUIDInfoWebDataItem.coopUUID est converti en
   GzDeviceInfo.cpDeviceId (classes11.dex).
2. TyDeviceCenter.Oooo000(String) lit
   DeviceBusiness.getDeviceInfo(String).cpDeviceId (classes16.dex).
3. TyCameraCenter.Oooo000(String) utilise l'adaptateur
   IotDevice.Oooo000(String) avant
   ThingIPCSdk.getCameraInstance().createCameraP2P(String)
   (classes16.dex).
4. La sélection du moteur P2P s'appuie aussi sur
   DeviceBean.skills/ProductBean et getDeviceP2PType
   (classes6.dex).

Notre client AOSU ne connaît pas encore cpDeviceId pour la C9C
externe : il cherche principalement coopUUID au premier niveau
de /v1/dev/getList, champ absent dans les résultats obtenus.
Le choix actuel reste appareil_tuya_unique_sans_categorie_video,
qui n'est qu'un repli heuristique.

## Outils et preuves conservés

- docs/C9C_BETA31_DIAGNOSTIC_COMPLET_RESULTAT_2026-11-09.md
- docs/AOSU_C9C_PONT_IDENTITE_CPDEVICEID_2026-11-09.md
- tools/aosu_sdk_route_offline.py : analyse statique locale.
- tests/test_aosu_sdk_route_offline.py : non-régression du
  routage et de la confidentialité.
- .github/workflows/aosu-route-audit.yml : tests automatiques.
- Rapport d'audit original AOSU complet : vérification locale
  17 DEX et 9 indices techniques sur 9.
- L'APK propriétaire d'environ 200 Mo reste seulement dans
  l'environnement de travail privé ; **aucun APK, DEX brut,
  SN, cpDeviceId, password, token ou clé n'est publié**.

## Ce qui reste à faire

1. Tracer la source utilisée par l'application AOSU pour renseigner
   DeviceBusiness / GzDeviceInfo.cpDeviceId, notamment les données
   UUIDInfoWebDataItem et les enregistrements d'appairage.
2. Déterminer si une API **de lecture authentifiée déjà validée**
   permet de récupérer cette référence propre au SN de la C9C.
3. N'adopter un ID Tuya que lorsque la correspondance explicite
   est unique et démontrée ; préserver l'état "non prouvé" sinon.
4. Ne modifier le routage, la SDP ou le moteur C9C autonome qu'après
   preuve technique et tests synthétiques, sans modifier C5L/H1L.
5. Ne demander qu'un **test global** lorsque la correction aura
   un intérêt réel, et non une succession de nouveaux boutons.

À ce stade : **aucun nouveau test utilisateur à faire**.


## Beta32 — correction après le rapport beta31

**Commit :** 6dcab5d975b95bfada87758538f2b59a49de9fff.

- Détection d'un défaut précis dans AosuCloudClient.refresh :
  seule la racine coopUUID était conservée pour la C9C autonome,
  alors que l'audit PTZ savait déjà détecter cpDeviceInfo.cpDeviceId.
- Nouveau module privé c9c_cp_reference_b32.py :
  récupère uniquement trois champs du même enregistrement AOSU associé
  au SN C9C : coopUUID racine, cpDeviceId racine, et
  cpDeviceInfo.cpDeviceId.
- Les identifiants invalides ou contradictoires sont rejetés, même
  si l'inventaire Tuya ne contient qu'un seul appareil.
- Une référence privée est tenue uniquement en RAM, jamais exposée
  en entité, état, journal ou rapport.
- Le bouton Diagnostic complet existant affiche une étiquette fixe
  « Origine référence AOSU ». Il n'utilise toujours ni réveil,
  publication MQTT, SDP, vidéo ou PTZ.
- Le sélecteur Tuya d'origine vérifie qu'un seul périphérique correspond
  exactement à la référence, sinon l'identité reste non confirmée.
- Aucun changement du système C5L ou du duo C9C3CA11 avec H1L.
- Tests automatisés réussis :
  https://github.com/tapion69/smart-aosu-cloud/actions/runs/42692565840
  et tests beta31 :
  https://github.com/tapion69/smart-aosu-cloud/actions/runs/42692566215

## Test unique après installation de la beta32

1. Mettre à jour l'intégration, redémarrer Home Assistant et recharger
   la carte. Aucun autre bouton préalable n'est nécessaire.
2. Lancer une seule fois **Diagnostic complet** en respectant les
   limites de reconnexion Tuya déjà établies.
3. Transmettre le résultat multi-lignes expurgé.
4. Examiner la nouvelle ligne « Origine référence AOSU » :
   - absente ou format invalide : le pont n'est pas disponible
     dans getList, ne pas inférer un identifiant ;
   - références contradictoires : arrêt de la liaison automatique ;
   - champ connu disponible, identité non prouvée : référence AOSU
     trouvée mais non correspondante dans l'inventaire Tuya ;
   - identité exacte : liaison corroborée sur un seul appareil Tuya.
5. Même en cas de liaison exacte, aucune lecture vidéo n'est
   garantie et aucune offre SDP supplémentaire n'a été envoyée.

## Si l'origine AOSU reste absente

Continuer l'analyse hors réseau du SDK Android sur
DeviceInfoRepoImpl / UUIDInfoWebDataItem pour identifier la source
du champ cpDeviceId dans les informations d'appairage. Envisager
uniquement une API AOSU de lecture déjà confirmée et autorisée,
sans inventer de valeur ni réinitialiser les trois caméras validées.

Aucun secret de connexion, SN, clé média ou productId n'est conservé
dans ce fichier.

## 10 novembre 2026 — enquête hors réseau sur le rapprochement Android

Après le diagnostic utilisateur beta32 :
- origine référence AOSU = absente ;
- SN Tuya absent, aucun cpDeviceId AOSU confirmé ;
- candidat Tuya Thing (code 4), sélection heuristique ;
- paramètres RTC présents mais aucune réponse SDP prouvée.

L'APK AOSU 5.10.12 d'origine (17 DEX) a été réanalysé
sans réseau ni compte. Les 9 constats du chemin de rapprochement
AOSU → TyDeviceInfoSource → cache indexé par cpDeviceId sont positifs.
Cela démontre un mécanisme SDK de cache local, **pas** l'existence du
cpDeviceId de cette C9C dans les données cloud déjà disponibles.

Nouveaux fichiers GitHub :
- tools/aosu_cp_cache_route_offline.py (analyseur reproductible) ;
- tests/test_aosu_cp_cache_route_offline.py (synthetic, sans APK) ;
- docs/AOSU_CP_CACHE_ROUTE_STATIC_2026-11-10.md (analyse) ;
- .github/workflows/aosu-cp-cache-audit.yml (CI).

Commit : 04e376e3685cbfe98e8908a5c67997ca10695fd2.
Tests GitHub réussis :
https://github.com/tapion69/smart-aosu-cloud/actions/runs/42861879809

**Version Home Assistant toujours 0.8.13-beta32** ; aucune nouvelle
version, aucun appel caméra, aucune modification des trois caméras
fonctionnelles. La prochaine action technique utile est de confirmer
une source réelle et autorisée de la liaison CP dans les données
d'appairage AOSU ; ne pas relancer les mêmes diagnostics ni inventer
un identifiant de caméra.

## Callback PlatformDeviceInfo du 10 novembre — enquête v3 (12 constats)

Les essais beta32 ont déjà prouvé : `Origine référence AOSU = absente`,
`SN Tuya absent`, sélection Tuya heuristique et absence de SDP.
Le bytecode Android 5.10.12 a maintenant été examiné jusqu'au
callback `TyDeviceInfoSource$init$1.OooO00o(PlatformDeviceInfo)`.

Trois faits supplémentaires ont été vérifiés hors ligne :

1. Le callback lit `PlatformDeviceInfo.cpDeviceId` ;
2. il appelle `DeviceBusiness.getDeviceInfo` ;
3. il appelle `GzDeviceInfo.setCpDataInfo` pour enrichir l'objet AOSU.

La méthode `DeviceWebService.OooOOOO()` utilisée pour la liste
AOSU n'accepte aucun argument métier supplémentaire au niveau de
sa signature Android. Cela ne prouve pas que les couches HTTP n'ajoutent
aucun en-tête ou paramètre de session ; en revanche, il n'existe
pas à cette interface un argument CP que notre appel aurait omis.

**Interprétation** : l'application peut obtenir la référence CP
par l'événement de sa couche Tuya Android, distinct des réponses
AOSU/ Tuya de Home Assistant. Cette conclusion demeure *statique* ;
la référence réelle de la C9C externe n'a pas été retrouvée.

Mises à jour GitHub :
- outil `tools/aosu_cp_cache_route_offline.py`, désormais 12 constats ;
- tests de confidentialité et absence de fausse identité ;
- rapport `docs/AOSU_CP_CACHE_ROUTE_STATIC_2026-11-10.md` enrichi.
- Commit : `2e442153a5a36de47ef7f37652b7aa7421959594`.
- Tests GitHub réussis : https://github.com/tapion69/smart-aosu-cloud/actions/runs/42864909848

### Condition concrète avant une beta33

Trouver une source autorisée **qui fournit réellement le cpDeviceId
de cette caméra précise** (par exemple des métadonnées d'appairage
disponibles sur le téléphone avec accord du propriétaire, ou une
API AOSU read-only vérifiée), avec provenance et concordance exacte
vers un seul appareil Tuya. Sans cette preuve, ni le champ Thing(4),
ni le productId, ni les trois réponses RTC ne doivent servir à
rediriger automatiquement l'offre vidéo.

Ne pas répéter `getList`, `getInfoBySn`, ou les cinq lectures
Tuya beta31 pour les mêmes champs. Ne pas inventer de
`coopUUID` pour appeler `getListByCoopUUIDList`.
Un téléphone Android non rooté n'autorise pas Home Assistant
à lire directement le cache privé de l'application AOSU.

**Aucune beta33 publiée** : l'intégration demeure
`0.8.13-beta32`. Aucun test utilisateur supplémentaire pour
cette analyse ; trois caméras existantes, vidéo, PTZ et entités
inchangés.

## 10 novembre 2026 — nouvel outil ADB sans root pour examiner les traces CP

L'APK officiel AOSU 5.10.12 emploie le package Android
`com.glazero.android` et contient des messages de diagnostic
concernant `cpDeviceId`, le chargement de la liste Tuya,
`ensureDeviceListForTargetDevice` et le rapprochement du cache.

Un outil **Windows facultatif** a été publié sous
`tools/windows/AOSU_CP_SANS_ROOT.ps1` avec un lanceur CMD et
une notice. Il utilise uniquement `adb devices`,
`adb shell pidof` et `adb logcat -d` filtré sur le PID AOSU.
Il ne lit pas les fichiers privés de l'application et ne
déclenche ni flux, ni réveil, ni PTZ.

Le propriétaire ouvre manuellement la C9C dans **AOSU officiel**,
puis le script relève les marques disponibles dans les journaux
du processus AOSU. Il ne renvoie que des indicateurs booléens,
et ne conserve aucun log, numéro de série ni identifiant CP.
Un marqueur présent ne prouve pas la correspondance avec la C9C.
La version publiée peut ne pas journaliser ces informations ;
leur absence dans logcat ne prouve pas qu'elles sont absentes
du cache privé.

**Vérification Windows sans téléphone réussie** :
https://github.com/tapion69/smart-aosu-cloud/actions/runs/42868671339

Un ZIP regroupant les trois fichiers Windows est également produit
par GitHub Actions après ses tests. C'est **un seul essai nouveau**
possible côté Android, sans répéter le diagnostic Tuya beta31/beta32.
La version installable HA reste **0.8.13-beta32**.

## 10 novembre 2026 — test réel ADB sans root Windows 1.2

Le téléphone et l'application AOSU ont été correctement détectés.
Le script a lu les journaux `logcat` du PID officiel mais n'a
détecté aucun des marqueurs CP/cache que nous avions identifiés
dans l'APK. `journal_aosu_lisible=true` ne certifie pas que les
messages recherchés ont été émis : seulement qu'il y avait des
lignes accessibles. **Le CP ID de la C9C reste inconnu.**

Résultat complet et ses limites :
`docs/C9C_ANDROID_ADB_1_2_RESULTAT_SANS_MARQUEURS_2026-11-10.md`.

La prochaine voie autorisée n'est pas une nouvelle offre SDP ou
un troisième essai du même logcat : demander au fournisseur, par
le titulaire du compte, les données d'appairage de la caméra et
la procédure d'accès aux données de diagnostic. AOSU décrit une
procédure de demande sur son site officiel. Il n'est pas certain
que le `cpDeviceId` puisse être communiqué.

**Version Home Assistant inchangée : 0.8.13-beta32**.
Les trois caméras fonctionnelles, leurs entités et leurs PTZ
restent inchangés.

## 10 novembre 2026 — audit croisé des deux APK réexpédiés, plus SDK natif

Audit complet : `docs/AUDIT_CROISE_APKS_COMPLET_LITE_C9C_2026-11-10.md`.
Commit : `8498e31026005cee0ae5894588c76e45bccdd9ac`.

L'original est bien l'APK 5.10.12 déjà analysé :
SHA256 `ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7`,
17 DEX et 75 bibliothèques ARM64. Le Lite (SHA256
`6a3692aa0dc2385f9d988ffbcf7a703249d426b022f78857d2b380748e790be1`)
contient seulement `classes11.dex` et `libglazero-security.so`,
tous deux identiques à l'original, mais sans manifeste Android ni SDK
P2P natif. Les anciens résultats négatifs de Lite n'étaient
pas représentatifs du moteur caméra.

Différence concrète : le code Android
`ThingSmartCameraP2PSync.innerConnect` traite `p2pPolicy`,
`sessionTid`, `clientTid`, configuration IPC, capacités
de l'appareil et mode local ; `TyCameraCenter` appelle
`ThingIPCSdk.createCameraP2P`, appuyé par `libThingP2PSDK.so`.
Le Python actuel construit au contraire un SDP AES/KCP et une offre
MQTT sans parité démontrée avec ce chemin natif.

La chaîne `sigQry` employée avant l'offre Python est visible dans
le code d'un gestionnaire de signal Wi-Fi Tuya
(`MQ_203_DataReceivedBean`, `WifiSignalListener.onSignalValueFind`),
pas dans le parcours caméra identifié. Ne plus traiter `sigQry`
comme protocole d'amorçage vidéo confirmé.

Toujours **aucune correspondance d'identité C9C AOSU/Tuya prouvée**.
La beta32 et les trois caméras C5L/H1L fonctionnelles restent intactes.
Ne pas lancer un nouvel essai SDP avant vérification hors réseau
de la parité SDK et preuve exacte d'identité. Le rapport complet
propose deux voies techniques (pont SDK autorisé ou moteur indépendant).

## 11 novembre 2026 — progression de l'analyse vidéo native

### Audit automatisé SDK Android / moteur Home Assistant

- Nouveau script `tools/aosu_c9c_sdk_python_coverage.py`.
- Test direct local sur l'APK complet AOSU 5.10.12 : **12 références
  SDK positives** (création P2P, fournisseur/catégorie/skills,
  p2pPolicy, sessionTid, clientTid, IPC, état local, décision LAN,
  configuration MQTT et deux bibliothèques natives).
- Tests synthétiques publiés et réussis dans GitHub Actions :
  https://github.com/tapion69/smart-aosu-cloud/actions/runs/42980890378
- Rapport : `docs/C9C_MATRICE_SDK_PYTHON_2026-11-11.md`.

### Comparaison binaire AES/CRC avec SDK Python indépendant MIT

- Nouveau test `tests/test_c9c_mqtt_reference_vectors.py`
  exécutant les véritables fonctions de `tuya_mqtt_offer.py`.
- Enveloppe MQTT 2.2 et offre **ASCII** : tramage, CRC32,
  AES-ECB et PKCS7 conformes aux vecteurs synthétiques
  indépendants de `roquerodrigo/tuya-ipc-p2p-sdk`.
- Chaîne `sigQry` protocole 22 précédant 302 présente dans
  l'implémentation indépendante. Le commentaire antérieur
  « seulement Wi-Fi » ne permet **pas** de rejeter cette requête.
- JSON avec Unicode : `ensure_ascii=False` actuellement, alors
  que l'implémentation indépendante laisse `ensure_ascii=True` ;
  différence observable hors réseau, aucune preuve d'impact réel C9C.
- **Cette parité concerne le SDK Python indépendant, pas
  le moteur natif AOSU** ; elle n'autorise pas à conclure
  que l'offre a été effectivement délivrée.
- Rapport : `docs/C9C_VECTEURS_MQTT_2026-11-11.md`.

### Prochaine correction utile

Concentrer les travaux hors réseau sur les paramètres de session
et de politique P2P, et sur la preuve du **même appareil
AOSU ↔ Tuya**. Examiner les différences d'identité, de
sélection du fournisseur, de rafraîchissement des clés,
de routage et de candidats ICE. Ne pas publier un nouveau test
caméra ou une beta33 sans modification démontrée et
testable. Aucun changement des trois caméras C5L/H1L
fonctionnelles ; HA toujours **0.8.13-beta32**.
