# Smart AOSU Cloud 0.8.13-beta30

L'analyse hors réseau des 17 DEX AOSU a identifié les valeurs
P2P_TYPE_PPCS = 2 et P2P_TYPE_THING = 4 dans ThingCameraConstants.
CameraConstant.getDeviceP2PType lit p2pType depuis DeviceBean.skills ;
IPCThingP2PCamera et IPCThingStationP2PCamera utilisent cette enum.

Le bouton Fiche Tuya affiche désormais uniquement une catégorie
PPCS, Thing, inconnue, ambiguë ou absente. Le type du candidat Tuya
ne prouve toujours pas sa liaison à la caméra AOSU.
Le service et les API beta29 restent les mêmes ; aucune commande,
connexion supplémentaire, offre MQTT, vidéo ou PTZ n'est ajoutée.
La temporisation beta28 est préservée.

Test : mettre à jour, redémarrer Home Assistant, utiliser une fois
Fiche Tuya et transmettre le seul résultat expurgé.
