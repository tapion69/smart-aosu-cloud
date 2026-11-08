# Smart AOSU Cloud 0.8.13-beta25 — analyse locale de l'APK SDK MQTT

La beta24 confirmait une seconde configuration IPC acceptée, avec WebRTC,
moto_id, auth, ICE et session RTC, mais aucun msid. Ce diagnostic examine
la présence de littéraux SDK Android sans réseau et sans tenter WebRTC.

- Nouveau bouton Analyser SDK APK sur la seule C9C autonome.
- Parcourt les tables de chaînes DEX d'un APK AOSU 5.10.12 vérifié par
  taille et SHA256, sans sauvegarder ni divulguer des chaînes.
- Recherche seulement les signatures statiques Jarvis MQTT/config,
  msid, canaux /av/u et /av/moto, domaines MQTT et SDK caméra.
- Si le gros APK original est disponible à côté de l'APK léger installé sous le nom Aosu_5.10.12_original.apks.apk,
  il est préféré. Si seul l'APK léger est présent, le diagnostic indique
  explicitement que l'analyse est partielle et non concluante.
- Protection contre les archives anormales (taille, nombre de DEX),
  une analyse toutes les 15 minutes et résultats expurgés.
- Aucun accès réseau, login, réveil, MQTT, vidéo, PTZ ni commande de
  caméra n'est déclenché par ce diagnostic.
- Tests synthétiques hors réseau ajoutés ; la validation avec l'APK
  complet de l'utilisateur reste à effectuer.

Après mise à jour, redémarrer Home Assistant et actualiser la carte.
Cliquer une seule fois sur Analyser SDK APK puis partager son état.
L'absence d'une chaîne ne prouve pas l'absence d'un protocole, surtout
dans la version allégée.
