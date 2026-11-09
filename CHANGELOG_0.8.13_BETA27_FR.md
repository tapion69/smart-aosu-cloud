# Smart AOSU Cloud 0.8.13-beta27 — fiche Tuya, identité C9C

La bêta26 a confirmé le réveil, les PUBACK et l'activation des compteurs
du SDK, sans aucune réponse SDP. L'audit AOSU du 9 novembre montre un
numéro de série concordant dans la fiche AOSU, mais aucune référence
Tuya ni aucun fournisseur P2P déclaré.

- Bouton « Fiche Tuya » pour la seule C9C autonome.
- Requête de lecture \`thing.m.device.get\` v4.1 déjà autorisée.
- Analyse en mémoire des champs SN, coopUUID, modèle et catégorie.
- Ne considère pas un seul appareil ni un modèle concordant comme
  une preuve d'identité ; seule une correspondance exacte SN ou
  référence coopUUID peut confirmer la liaison.
- Résultats anonymisés ; aucune valeur de caméra/compte/clé n'est émise.
- Aucune publication MQTT, réveil, SDP, vidéo, PTZ ou écriture locale.
- Les moteurs C5L et H1L, ainsi que les offres beta26, sont inchangés.
- Tests synthétiques et de garde-fous ajoutés.

Mettre à jour, redémarrer Home Assistant et actualiser la carte.
Cliquer une fois sur Fiche Tuya. Transmettre uniquement le statut visible.
Une lecture refusée ou un champ manquant n'établit pas que l'identité
est différente, mais invite à chercher l'information ailleurs.
