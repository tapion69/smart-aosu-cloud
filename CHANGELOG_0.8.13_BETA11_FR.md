# 0.8.13-beta11 — classification passive MQTT C9C

- Conserve les deux abonnements MQTT déjà observés et le test manuel de 20 secondes.
- Classe l'enveloppe `2.2` et le résultat du déchiffrement en mémoire avec la clé locale RTC, sans conserver de contenu.
- Compte les protocoles `22` et `302`, les types `offer`, `answer`, `candidate`, `disconnect`, et les correspondances exactes de l'émetteur/destinataire à l'appareil ou utilisateur de session.
- Les seules données exposées à Home Assistant sont des compteurs bornés. Aucune clé, identifiant ou trame n'est publié.
- **Aucune offre vidéo/commande PTZ n'est envoyée** ; aucun changement aux moteurs C5L/H1L ou au décodeur.

Échantillon de départ : 19 publications sur le canal appareil et 0 sur le canal moto pendant le direct officiel. Le sens de ces messages est encore à établir par la classification.
