# Smart AOSU Cloud 0.8.13-beta18 — vérifier la veille avant d'envoyer un réveil

La bêta17 a montré cinq notifications non vidéo, un `disconnect` d'une autre session, mais aucune SDP pour Home Assistant. Tuya documente `wirelessWake(devId)` dans son SDK et le DP 149 `wireless_awake` sur les caméras basse consommation.

- Ajoute un détecteur DP 149 strictement borné pour l'inventaire Tuya existant et le flux MQTT déjà déchiffré.
- Ajoute au rapport **Observer MQTT** la présence de DP149 dans l'inventaire, un indice basse consommation explicite si présent, et le nombre de rapports DP149 `true`, `false` ou non booléens.
- Ignore les publications retenues (retained) pour le comptage dynamique des états DP149.
- N'assimile pas une absence de rapport à une absence de prise en charge, et ne déduit pas aveuglément l'état éveillé de la valeur booléenne.
- Ne modifie aucun protocole d'offre vidéo, le réveil de la caméra, les commandes PTZ ou les moteurs C5L/H1L.

**Test manuel** : mise à jour, redémarrage, « Observer MQTT », direct officiel pendant 20 secondes ; transmettre le seul texte de la carte. Pas de réveil expérimental envoyé.
