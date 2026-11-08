# Smart AOSU Cloud 0.8.13-beta21 — même session MQTT, réveil puis offre

La beta20 obtenait PUBACK et DP149=true, mais fermait la connexion MQTT
avant d'ouvrir une nouvelle session pour l'offre vidéo. La beta21 conserve
une seule connexion MQTT/TLS, sur une unique caméra C9C autonome manuellement
sélectionnée, pendant les deux étapes.

- Réveil QoS1 puis offre SDP sur le même socket et abonnement MQTT.
- Pas d'offre si le réveil n'a pas été acquitté ET si DP149=true n'a pas
  été reçu dans les 25 secondes.
- Cooldown partagé de dix minutes, aucun essai automatique ni PTZ.
- Rapport anonymisé : réveil, PUBACK réveil, offre réellement envoyée,
  PUBACK offre, délais réveil et confirmation→offre.
- Chemins C5L et H1L inchangés ; le réveil isolé reste disponible.

**Test** : mettre à jour, redémarrer Home Assistant, recharger la carte,
fermer le direct AOSU, attendre la temporisation, cliquer une seule fois
sur « Réveil + vidéo » puis transmettre État. La réponse SDP et les images
ne sont pas encore validées sur le matériel externe.
