# Smart AOSU Cloud 0.8.13-beta12 — vérification passive du format de session C9C

Après la bêta11, le canal `smart/mb/in` a révélé cinq messages WebRTC `302` déchiffrables pendant le direct officiel (un `answer`, quatre `candidate`). La clé locale utilisée et le champ `from` correspondent à l'appareil Tuya expérimental, sans garantir encore sa correspondance au compte AOSU.

- Étend la classification passive des en-têtes : `path=mqtt`, présence `sessionid` et `moto_id`, `from` et `to` selon une comparaison stricte en mémoire.
- Pour les réponses `answer` : compte la présence d'un SDP et d'un marqueur `AES/KCP` sans exposer le SDP.
- Pour les `candidate` : compte la présence d'un candidat ICE sans exposer ses détails.
- Toujours zéro offre vidéo, commande PTZ, journal brut, identifiant ou secret.
- Aucun changement au moteur C5L/H1L, à la sélection de la C9C, ni à ses offres MQTT.

**Test** : une observation manuelle, ouverture du direct officiel AOSU pendant 20 secondes. Résultat strictement indicatif.
