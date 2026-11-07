# Smart AOSU Cloud 0.8.13-beta4 — diagnostic réponse MQTT C9C autonome

L'essai sur une C9C autonome externe a atteint le RTC et un envoi MQTT de l'offre SDP, mais aucune réponse SDP n'a été reçue après 20 secondes. Une unique réponse sur le topic de session était auparavant classée « protocole inattendu ».

- Distingue les réponses au `sigQry` (protocole 22, demandé par le client lui-même) des réponses de vidéo (protocole 302) et des autres protocoles ; **le message observé n'est pas encore identifié sur l'installation externe**.
- Compte sans contenu privé les réponses 302 de format inattendu ou de type non pris en charge.
- Enrichit le bouton **État** de la carte C9C avec ces compteurs.
- Aucun changement au format de l'offre, aux échanges P2P, au décodeur, aux commandes PTZ ou aux limites de réessai. Aucune capture, aucun identifiant et aucun paquet de signalisation ne sont enregistrés ou retournés.

**À tester :** une seule tentative manuelle après mise à jour. Ne pas enchaîner les essais. Si aucune réponse SDP n'arrive, partager uniquement `dernier_resultat.signalisation_b89` en vérifiant la confidentialité de la sortie.
