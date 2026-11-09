# Smart AOSU Cloud 0.8.13-beta28 — corriger la limitation Fiche Tuya

La bêta27 pouvait retourner limite_login_une_heure : sa session
authentifiée est considérée valide pendant vingt minutes, mais la
reconnexion manuelle restait bloquée une heure. Même l'inventaire
pouvait être refusé trente minutes après une lecture.

## Correction limitée à Fiche Tuya
- Session en RAM réutilisée si âgée de moins de 20 minutes.
- Inventaire Tuya de même UID réutilisé jusqu'à 30 minutes, lecture seule.
- Si une nouvelle connexion est nécessaire, une demande manuelle
  est autorisée **au plus une fois toutes les vingt minutes**, en
  tenant compte des précédentes tentatives de connexion OEM.
- La limitation d'une heure pour les autres outils et leur logique
  d'authentification sont conservées.
- La limite de cinq minutes de la lecture de fiche Tuya reste active.
- Aucun réveil, MQTT, SDP, vidéo, PTZ ou nouvelle API.
- Protection contre des essais répétés et tests de régression hors réseau.

Mettre à jour la version beta28, redémarrer Home Assistant,
rafraîchir la carte, puis cliquer UNE seule fois sur Fiche Tuya.
En cas de refus du serveur, ne pas répéter les connexions.
