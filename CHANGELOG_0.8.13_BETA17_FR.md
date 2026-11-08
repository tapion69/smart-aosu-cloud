# Smart AOSU Cloud 0.8.13-beta17 — classifier les échanges MQTT sans modifier le P2P

Observations du dernier essai C9C : IPC-v4 accepté, moto_id appliqué, 7 publications reçues, dont 6 protocoles non vidéo et 1 trame 302 avec session non concordante ; 4 requêtes STUN traitées ; 0 SDP appartenant à la session Home Assistant.

- Diagnostics supplémentaires dans `dernier_resultat.signalisation_b89` : quatre plages de protocoles non 22/302, émission de la part de l'appareil, types de messages vidéo.
- Classe les réponses 302 hors session (answer/candidate/disconnect/autre) et vérifie la présence d'un SDP sans retourner sa valeur.
- Aucun identifiant, SDP, IP, clé ou trame brute exposé ou écrit. Les compteurs sont facultatifs et n'apparaissent que sur l'essai manuel C9C autonome.
- **Aucune modification des commandes, de l'offre MQTT, du routage RTC, des limites, du décodeur, de la C5L ou du H1L.**

Test : mettre à jour, redémarrer HA, exécuter une seule tentative volontaire puis fournir `dernier_resultat.signalisation_b89`. Une SDP hors session n'est pas considérée comme SDP valide.
