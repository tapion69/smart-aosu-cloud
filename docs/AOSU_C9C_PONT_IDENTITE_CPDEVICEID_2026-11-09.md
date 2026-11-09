# Smart AOSU — parcours de liaison caméra AOSU vers Tuya

Analyse statique du 9 novembre 2026. APK AOSU 5.10.12 complet (17 DEX)
déjà récupéré par le propriétaire. Aucune opération sur les caméras,
aucune authentification, aucune donnée privée dans ce document.

## Chaîne technique vérifiée dans le bytecode

1. classes11.dex : le convertisseur
   UUIDInfoWebDataItem.OooO0O0() lit le champ coopUUID et écrit
   GzDeviceInfo.cpDeviceId.
2. classes16.dex : TyDeviceCenter.Oooo000(String) demande à
   DeviceBusiness.getDeviceInfo(String) la fiche interne puis lit
   GzDeviceInfo.cpDeviceId.
3. classes16.dex : TyCameraCenter.Oooo000(String) passe par
   IotPlatformSPI, IotPlatform.getDevice(), puis
   IotDevice.Oooo000(String) avant d'appeler
   ThingIPCSdk.getCameraInstance().createCameraP2P(String).
4. classes6.dex : CameraConstant.getSdkProvider(DeviceBean)
   consulte DeviceBean.getSkills() et getProductBean().
   ThingSmartCameraP2PSync.innerConnect() utilise
   getDeviceP2PType(Map) pour la sélection P2P.

Le convertisseur AOSU --> DeviceBusiness --> cpDeviceId -->
adaptateur IotDevice --> caméra Thing est donc une piste étayée
par les instructions du SDK.

**Important :** cette preuve statique n'indique pas quelle valeur
cpDeviceId possède la C9C externe. Elle ne valide ni l'ID Tuya
retenu par la beta31 ni l'ouverture vidéo.

## Différence dans notre intégration

Le client api.py lit actuellement la référence coopUUID seulement
dans le champ racine de l'enregistrement AOSU de /v1/dev/getList.
Le rapport beta31 a constaté l'absence de cette référence pour
la caméra C9C autonome.

L'application Android dispose en revanche d'un cache d'appareil
DeviceBusiness et d'un chemin de conversion vers
GzDeviceInfo.cpDeviceId. Cette structure peut être remplie par
différentes réponses de service ou par des données d'appairage.
Elle n'est pas à ce stade accessible de manière démontrée à
notre intégration Home Assistant.

L'égalité du productId entre inventaire Tuya et fiche Tuya,
le p2pType Thing=4, et les trois configurations RTC acceptées
ne sont pas une correspondance AOSU/Tuya.

## Précautions et critères de correction

- Ne PAS remplacer l'ID de la caméra par un hash, un SN,
  un productId, un ID MQTT ou le seul appareil Tuya trouvé.
- La correction ne sera considérée justifiée que si nous
  retrouvons une référence cpDeviceId explicite associée à la
  C9C AOSU et égale à un ID de la fiche Tuya.
- Vérifier la provenance de la donnée, les espaces de noms
  et les cas où une station H1L est présente.
- Les trois caméras fonctionnelles (C5L et 2 C9C via H1L)
  et leurs entités, PTZ, vidéo et commandes restent inchangées.
- Ne reprendre les tests SDP qu'après confirmation de la cible
  ou preuve d'une autre différence exploitable.
- Le broker qui accuse réception d'une offre ne prouve pas
  que la caméra cible a traité cette offre.

## Outil et tests mis en place

- tools/aosu_sdk_route_offline.py : audit local de l'APK/APKS
  original, ne retourne que neuf indicateurs statiques et
  n'effectue aucune requête Internet.
- tests/test_aosu_sdk_route_offline.py : vérifie que les
  résultats statiques ne promettent jamais une identité
  ni une vidéo réelle, et préserve la distinction identité
  exacte / sélection heuristique.
- .github/workflows/aosu-route-audit.yml : vérifie le script
  et les tests automatiquement à chaque modification du
  routage ou de l'outil.

Exécution locale facultative, sans déposer l'APK dans GitHub :

    python tools/aosu_sdk_route_offline.py CHEMIN_VERS_APK_ORIGINAL

Validation locale sur le fichier original fourni : 17 DEX,
9 indicateurs détectés sur 9. Cela ne prouve toujours pas
l'identité réelle de la C9C.

## Prochain axe sans test utilisateur

Poursuivre le traçage statique de la source qui remplit le
cache DeviceBusiness et le champ cpDeviceId, notamment
UUIDInfoWebDataItem et les données d'appairage. Vérifier
ensuite si cette source est accessible au compte AOSU
via une opération de lecture explicitement autorisée.
N'ajouter un endpoint de test qu'après avoir établi
ses paramètres exacts et ses limites.

Version installable maintenue : **0.8.13-beta31**.
