# Smart AOSU Cloud 0.8.13-beta8 — examiner RTC C9C sans démarrer de vidéo

L'analyse du PCAP privé confirme TURN/UDP/KCP côté application AOSU. Smart AOSU Cloud reçoit une configuration RTC Tuya et publie une offre MQTT mais n'obtient pas de réponse SDP. L'identité Tuya de la C9C demeure non confirmée.

- Ajoute un bouton **Examiner RTC**, pour une lecture RTC volontaire de l'unique candidat Tuya sans envoi d'offre, sans P2P et sans commandes caméra/PTZ.
- Expose uniquement des indicateurs de présence pour `moto_id`, `pv` (2.2/2.3), ICE, TURN, relais TCP et UDP, clé locale et identifiant de session ; jamais les valeurs.
- Conserve les limites d'inventaire/authentification/RTC et les validations explicites des appels.
- Nettoie le bootstrap média temporaire après ce diagnostic.
- Ne touche ni à la sélection du candidat vidéo, ni aux sujets MQTT, ni au décodeur HEVC, ni aux contrôleurs des caméras C5L et H1L.

**Test externe :** mise à jour, redémarrage HA, puis un clic sur **Examiner RTC** sans lancer la vidéo. Transmettre uniquement le résumé anonymisé.
