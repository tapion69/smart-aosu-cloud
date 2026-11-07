# Smart AOSU Cloud 0.8.10 — Interface épurée

- Cartes C5L et C9 : suppression des avertissements jaunes, des contrôles et diagnostics réservés au développement et des métadonnées répétitives visibles.
- Conservation uniquement de Démarrer/Arrêter, Plein écran, directions PTZ et STOP.
- Deux cartes C9 : plein écran MJPEG sans modifier la session réseau.
- Vérification PTZ automatique en lecture seule, dès l’affichage de la carte et régulièrement tant qu’elle est ouverte. Plus besoin de cliquer sur État PTZ.
- Autorisation de mouvement toujours validée par Home Assistant, par caméra et uniquement lorsque les conditions de sécurité sont réunies. Les protections STOP et le watchdog restent inchangés.
- Aucun changement aux moteurs vidéo, KCP, RTC, services de commande ou données privées.

> Une autorisation PTZ stable déjà enregistrée est réutilisée. Pour un appareil non autorisé, l’activation initiale reste volontairement requise côté Home Assistant.
