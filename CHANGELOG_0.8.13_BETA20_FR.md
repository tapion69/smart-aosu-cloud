# Smart AOSU Cloud 0.8.13-beta20 — réveil et vidéo C9C dans un seul parcours

La commande de réveil bêta19 obtient un signal `DP149=true`, mais le test séparé n'a toujours aucune réponse SDP. La bêta20 tente de supprimer l'intervalle entre les deux actions.

- Bouton **Réveil + vidéo** : clic volontaire, une seule configuration RTC IPC-v4 et un seul réveil puis offre.
- Attend MQTT PUBACK et au moins un DP149=true dans la fenêtre de 25 s avant de transmettre l'offre.
- Aucun envoi d'offre si réveil non confirmé ; résultat exposé uniquement sous `dernier_resultat.reveil_et_video` (statuts et compteurs).
- Cooldown de 10 minutes partagé avec le bouton **Tester le réveil** : pas de commande supplémentaire dans cette période.
- Ne change pas le format MQTT/SDP ni les autres moteurs vidéo et PTZ ; C5L et H1L restent sur leurs chemins existants.
- Aucune clé ou identité d'appareil dans le rapport, le code ou les tests.

Une réussite de DP149 ne garantit pas une réponse SDP ni de la vidéo. Ne pas automatiser les essais.
