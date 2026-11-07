# Smart AOSU Cloud 0.8.13-beta1 — caméra C9C autonome

- Ne plus créer d'entités C9 H1L sans station H1L **et** au moins une C9C3CA11 détectées dans l'inventaire.
- Les deux C9C3CA11 sur station H1L conservent leurs contrôleurs et numéros de caméra historiques.
- Sur un compte contenant exactement une C9C autonome sans station, crée une entité caméra de **test vidéo seulement**.
- Ajoute un service manuel à trois confirmations qui tente le protocole vidéo P2P de la C5L, avec sélection Tuya par identifiant exact ou, sous conditions strictes, candidat IPC unique.
- Nouvelle carte Lovelace `smart-aosu-c9c-autonome-b1` avec Lecture / Arrêt / État / Plein écran, sans boutons PTZ ni redémarrage automatique.
- Aucun changement au PTZ C5L ou C9/H1L, ni à l'importation des ressources APK Lite + OEM.
- **Pas encore validé avec une C9C autonome réelle.**
