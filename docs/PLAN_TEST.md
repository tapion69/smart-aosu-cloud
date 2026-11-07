## Nouveau : installation dans HA depuis le navigateur

Contrôler les 2 sélecteurs, la validation des fichiers, la création automatique du dossier, puis le formulaire de connexion.

# Plan de validation sur une seconde installation — 0.8.10 R1

Conserver les résultats séparés pour chaque caméra. Ne **jamais** tester le PTZ d'une C9 dont l'identité n'est pas confirmée.

1. **Préparation** : sauvegarde HA effectuée ; prérequis locaux valides ; note de version de HA Core / OS et du modèle exact de caméra/station.
2. **Démarrage** : intégration ajoutée sans erreur ; inventaire AOSU accessible ; entités disponibles.
3. **C5L** (si présente) : lancer le direct → image → plein écran → arrêter → relancer une fois.
4. **C9/H1L** (si présentes) : renseigner `ip_station`, identifier les numéros 1 et 2 → démarrer la vidéo de chaque caméra séparément → plein écran → arrêter puis relancer une fois.
5. **PTZ C5L** : avec l'application AOSU officielle accessible, tester un mouvement bref et vérifier son arrêt physique au relâchement. Continuer avec les autres flèches et STOP uniquement après cette vérification.
6. **PTZ C9** : ne jamais supposer que les flèches actives suffisent à prouver la sécurité. Faire d'abord une autorisation d'essai temporaire avec l'action `smart_aosu_cloud.autoriser_essai_ptz_c9_b159` (numéro C9 vérifié, confirmations du test et du STOP disponible). Tester un mouvement très court, vérifier **physiquement** le STOP. Si le STOP échoue, reprendre le contrôle avec l'application officielle et abandonner les essais. Seule une constatation réelle du mouvement ET de l'arrêt justifie `smart_aosu_cloud.autoriser_ptz_c9_stable`. La permission est indépendante pour chaque C9.
7. **Stabilité** : fermer les directs, redémarrer HA, réouvrir chaque vidéo, vérifier si les permissions PTZ persistantes correspondent toujours au bon appareil. Ne pas forcer une autorisation devenue invalide.
8. **Retour** : remplir `docs/FICHE_RETOUR_TEST.md` sans données privées et sans capture de caméra.

Les étapes réseau, identité et authentification peuvent dépendre de l'environnement externe ; échec externe = compatibilité non démontrée, pas nécessairement régression de la 0.8.10 locale.
