# Smart AOSU Cloud 0.8.13-beta19 — première commande de réveil C9C autonome

La bêta18 confirme un DP149= true pendant le direct AOSU officiel. Selon le protocole Tuya basse consommation, il s'agit d'un rapport de réveil possible. Une intégration Tuya indépendante MIT (JustDauren/tuya-peephole-integration) utilise un topic `m/w/<id>` et une valeur CRC32 big-endian calculée depuis la clé locale.

- Ajout d'une **commande de réveil expérimentale et explicite**, réservée à la C9C autonome unique.
- Publication MQTT sur TLS vérifié, QoS1, une seule fois, sans SDP ni vidéo ni PTZ.
- Contrôle de l'acquittement du broker puis observation DP149 en mémoire pendant au maximum 25 secondes.
- Cooldown de dix minutes, aucune tentative automatique ; refus si un direct HA est en cours.
- Ne renvoie aucun identifiant, clé, CRC, adresse, SDP ou message brut.
- Ne touche pas aux contrôleurs C5L/H1L ; le succès réel sur caméra AOSU reste à valider.

**Essai** : sans direct ouvert dans AOSU, appuyer une seule fois sur « Tester le réveil », transmettre le résultat, ne pas relancer immédiatement.
