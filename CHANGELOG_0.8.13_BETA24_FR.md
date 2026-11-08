# Smart AOSU Cloud 0.8.13-beta24 — diagnostic IPC v2

Suite au diagnostic beta23 (WebRTC déclaré, auth et moto_id présents,
msid absent), une seconde lecture IPC est proposée.

- Bouton Examiner IPC v2 pour la C9C autonome unique.
- Appel HTTPS thing.m.ipc.config.get version 2.0 déjà autorisé.
- Seuls des indicateurs anonymes sont retournés.
- Temporisation partagée avec le RTC de cinq minutes.
- Aucune publication MQTT, réveil, offre SDP, vidéo ou PTZ.
- Aucun changement des moteurs C5L et C9/H1L.
- Test de câblage hors réseau ajouté.

Mettre à jour, redémarrer HA, actualiser la carte, puis cliquer
sur Examiner IPC v2 une fois. Transmettre le résultat visible.
Une absence de msid ne prouve pas une absence de WebRTC.
