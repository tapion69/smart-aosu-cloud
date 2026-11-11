# C9C autonome — préparation du candidat ICE avant l'offre

Branche **expérimentale uniquement**, pas de mise à jour installable.

La beta32 ouvre actuellement un candidat ICE contrôlé **après**
la publication d'une offre MQTT. Même si l'ouverture locale
du port UDP échoue, elle attend une réponse SDP qui n'arrivera
probablement pas. Pour la C9C autonome seulement,
cette branche prépare le candidat **avant le réveil et l'offre**.

- Si le candidat est indisponible : statut fixe
  `ice_local_indisponible_offre_non_envoyee`.
- Aucun réveil, offre, candidat ou commande caméra envoyé par
  le programme dans ce cas.
- Si le candidat est prêt : les mêmes messages sont transmis
  dans l'ordre existant `sigQry`, offre puis candidat.
- L'ICE local est fermé dans tous les cas (y compris abandon).
- Le parcours C5L/H1L n'utilise pas le nouveau précontrôle.
- Pas de journaux sensibles, IP, SDP ou clé en sortie.

Tests hors réseau avec socket MQTT/SSL entièrement simulée :
candidat absent, présent et chemin historique, plus les
tests C9C de topologie. Ils n'ouvrent aucun port réel.

**Ce correctif n'est pas une solution à l'identité manquante.**
Il évite un échec inutile et isole proprement une condition
prérequise. Il ne permet pas de conclure qu'un vrai candidat
produira la vidéo. Brancher l'intégration à une caméra exige
toujours un examen de la liaison AOSU/Tuya et de la conformité
du protocole P2P.
