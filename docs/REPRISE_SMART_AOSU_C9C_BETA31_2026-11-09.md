# Point de reprise — Smart AOSU Cloud / C9C autonome

Établi le 9 novembre 2026. Conservé pour faciliter la reprise d'une autre discussion.

## Dépôt et état installable

- GitHub : tapion69/smart-aosu-cloud, branche main.
- Dernière version installable : **0.8.13-beta31**.
- Les nouveaux fichiers d'analyse SDK ne changent pas le manifeste et
  ne nécessitent aucune installation dans Home Assistant.
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
