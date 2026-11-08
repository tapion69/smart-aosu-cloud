# Smart AOSU Cloud 0.8.13-beta13 — lecture RTC IPC-v4 pour C9C autonome

- Le trafic MQTT officiel confirme 1 réponse SDP AES/KCP et 4 candidats, mais HA ne reçoit aucune réponse à sa propre offre.
- Différence à vérifier : `thing.m.rtc.config.get` utilisé par HA vs `m.ipc.v4.rtc.config.get` utilisé par une implémentation IPC indépendante.
- Nouveau bouton manuel **Comparer RTC IPC** ; il interroge uniquement la méthode v4 pour le candidat C9C unique, en lecture cloud, avec les limites existantes.
- Retourne uniquement un état énuméré, un booléen d'acceptation, la disponibilité du bootstrap média, et des champs de présence anonymisés.
- N'envoie aucun MQTT PUBLISH, n'active ni vidéo ni PTZ ; n'enregistre pas de clé, ID, réponse complète ou SDP.
- Ne modifie pas les chemins de lecture vidéo C5L et H1L ; la C9C n'adoptera pas la méthode v4 tant que l'essai n'aura pas confirmé sa validité.
