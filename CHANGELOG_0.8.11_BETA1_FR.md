# Smart AOSU Cloud 0.8.11-beta1 — 7 novembre 2026

- Génération locale et persistante d'un `profile.json` expérimental si absent, sans écraser le profil existant.
- Ajout de l'adresse IPv4 privée de la station H1L dans la configuration initiale et les options.
- Les services C9 réutilisent l'IP d'intégration quand la carte ne fournit pas d'IP ; une IP par carte reste prioritaire.
- La carte C9 actuelle `c9-live-b146.js` accepte l'absence de `ip_station` dans son YAML.
- Préservation du cœur vidéo/PTZ existant, des STOP et de l'autorisation manuelle PTZ C9.
- Mise à jour du contrôle local hors réseau, de la documentation et des traductions.
- **Pas de bundle APK ni de ressources OEM dans le dépôt. Aucun test live AOSU/HA externe effectué.**
