# Audit statique AOSU 5.10.12 — P2PType

9 novembre 2026. Analyse locale des 17 DEX de l'APK complet,
sans aucune interaction avec les caméras ou le cloud.

Dans classes6.dex :
- ThingCameraConstants$P2PType : PPCS=2 et THING=4.
- P2PType.intToEnum : pour un nombre inconnu, le SDK contient un
  repli Thing, qui ne prouve pas le protocole effectif.
- CameraConstant.getDeviceP2PType(Map) lit la clé p2pType
  avec des conversions Integer, Float et Double.
- CameraConstant.getSdkProvider(DeviceBean) lit skills et prend aussi
  en compte sous-appareils, catégorie et virtualisation.
- IPCThingP2PCamera.createDevice et
  IPCThingStationP2PCamera.createDevice appellent intToEnum.

Le diagnostic beta29 a confirmé seulement la présence de p2pType
et skills, pas le code réellement présent. Beta30 ajoute une
classification des nombres 2 et 4 dans skills, sans exporter
d'autres nombres, UID, SN, nom ni valeur de configuration.

La présence d'un type ne suffit pas à identifier la C9C et
ne prouve pas la réception d'une offre SDP.
