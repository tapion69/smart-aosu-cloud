# Smart AOSU Cloud 0.8.13-beta9 — moto_id RTC dans l'offre C9C

- Ajoute une extraction sécurisée de `moto_id` à partir de chemins prédéfinis et d'une valeur unique de la configuration RTC en mémoire.
- Seul le **direct manuel expérimental C9C autonome** peut utiliser cette valeur dans les messages MQTT offer/candidate/disconnect.
- Sans valeur confirmée par la structure RTC, maintient le comportement antérieur (champ vide).
- Affiche uniquement la provenance catégorisée et si le `moto_id` a été inséré ; jamais les identifiants ou secrets.
- Aucune modification des commandes PTZ, des contrôleurs C5L et H1L, des paramètres réseau, du décodeur ou des limites de réessai.
- Le diagnostic RTC et le bouton « Examiner RTC » restent strictement en lecture seule.

**Test :** mettre à jour et redémarrer HA ; une seule tentative volontaire sur la C9C, puis afficher État et transmettre `dernier_resultat` expurgé. Ne pas automatiser ou enchaîner les essais.
