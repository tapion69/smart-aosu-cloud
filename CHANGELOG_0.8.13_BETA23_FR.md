# Smart AOSU Cloud 0.8.13-beta23 — audit du chemin WebRTC alternatif

La beta22 a confirmé le réveil, l'offre AES/KCP envoyée et acquittée sur
une même connexion MQTT, mais toujours aucune réponse SDP. Certaines
caméras Tuya basse consommation utilisent une signalisation WebRTC distincte.

- Comparer WebRTC : lecture RTC IPC-v4 existante, vérification des champs
  moto_id, auth WebRTC et msid explicite. Résultat anonyme uniquement.
- Tester canal WebRTC : si un msid explicite et unique est présent, tente
  une connexion TLS/MQTT et souscription /av/u/<msid>. Aucune publication.
- Si les paramètres sont absents, ne devine pas les valeurs et n'envoie
  aucun SDP ni offre non conforme. Seconde API Jarvis non appelée.
- Aucun changement au réveil ou vidéo AES/KCP, à C5L/H1L, au PTZ.
- Nouveau test de diagnostic hors réseau. Cooldown RTC inchangé ; test
  de souscription limité à une fois toutes les dix minutes.

Mode opératoire : mettre à jour, redémarrer HA, rafraîchir le navigateur,
puis cliquer sur Comparer WebRTC. Partager uniquement le diagnostic visible.
