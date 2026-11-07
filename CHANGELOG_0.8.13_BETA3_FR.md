# Smart AOSU Cloud 0.8.13-beta3 — C9C autonome : diagnostic et essai RTC contrôlé

- Premier essai externe de la beta2 : une seule C9C AOSU autonome et un appareil Tuya, mais aucune catégorie caméra reconnue ; aucun RTC, MQTT ou RTP n’a été lancé.
- Pour ce seul cas, après action manuelle **Essayer la vidéo**, on peut essayer une configuration RTC du seul appareil Tuya, sous réserve de l'identité AOSU C9C déjà établie. La sélection demeure **non confirmée** : elle ne suppose pas qu'une absence de catégorie équivaut à une caméra.
- Refus si plusieurs appareils Tuya sans candidat vidéo, si le candidat unique se présente explicitement comme une catégorie non vidéo, si l'identité AOSU de la caméra est absente, ou si le compte contient une station H1L ou plusieurs caméras.
- Les requêtes RTC sont soumises au contrôle distant : si la réponse ne fournit pas de session vidéo valide, les étapes de démarrage MQTT/média ne sont pas lancées. Aucun PTZ C9C autonome.
- Diagnostic en lecture seule complété avec la décision du serveur concernant la configuration RTC et la présence d’une réponse RTC.
- Aucun changement aux contrôleurs vidéo/PTZ validés des C5L et C9C3CA11/H1L. Aucune APK et aucune donnée personnelle incluse.

**Statut : expérimental non validé sur cette C9C.** Effectuer au plus une tentative après mise à jour et relever `dernier_resultat` si l’image ne vient pas. Une unique entrée Tuya n’est pas à elle seule une preuve d’identité.
