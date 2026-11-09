# Smart AOSU Cloud 0.8.13-beta29 — analyse d'identité C9C autonome

La beta28 interroge correctement \`thing.m.device.get\` pour l'unique
candidat Tuya, mais le diagnostic « SN exact : non » ne distinguait pas
l'absence du SN d'une valeur présente sans égalité. Aucun lien avec
l'identité AOSU n'était confirmé.

## Modifications

- Sur le **même bouton Fiche Tuya**, états détaillés SN, référence,
  modèle et catégorie : absents / non égaux / exacts / non comparables.
- Présence de productId (racine et bloc productBean), skills, capacités,
  p2pType, p2pConfig et indicateurs booléens de support P2P.
- Toutes les valeurs privées restent en RAM ; les réponses Home Assistant
  sont constituées exclusivement de booléens et d'états préapprouvés.
- \`productId\`, modèle C9C ou ID Tuya répété par la réponse ne
  prouvent **pas** l'identité AOSU/Tuya.
- Aucun nouvel appel réseau et aucune publication MQTT, réveil, SDP,
  vidéo, PTZ ou capture. Aucune modification C5L et H1L.
- Temporisations beta28 préservées. Tests synthétiques et d'isolation.

## Test

Mettre à jour, redémarrer HA, actualiser la carte, utiliser **Fiche Tuya**
une seule fois. Communiquer uniquement le texte de statut affiché.
Si la limite de reconnexion est encore active, ne pas forcer les essais.
