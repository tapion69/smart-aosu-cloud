# Smart AOSU — Contrat RTC natif versus offre Python, deuxième refus C9C

**14 novembre 2026 — étude sur APK propriétaire de l'utilisateur, lecture hors ligne seulement.**  
**Branche `research/c9c-http-refusal-native-parity` — aucune nouvelle bêta vidéo, aucune commande caméra.**

## Résultat du dernier essai physique

La C9C autonome chez le frère est toujours **sans vidéo Home Assistant validée**.
Le test `0.8.13-beta44-rc3`, après la correction des huit champs de l'offre HTTP, a renvoyé :

- `requete_http_effectuee=true`
- `serveur_accepte=false`
- `rejet_explicite=true`
- `categorie_refus=indeterminee`, `code_erreur_present=true`
- `methode_cible=candidat_unique_autorise_manuellement`

La comparaison SN officielle AOSU↔cache AOSU de HA est exacte, **sans** correspondance Tuya démontrée. Il ne faut pas assimiler `candidat_unique` à une preuve d'identité.

## Preuves directes nouvelles : encodeur natif et jetons

Binaire local propriétaire : `libThingP2PSDK.so`, SHA-256
`c9032dcf37f72fc7ad28835a02c4e66a814597380f10c132d042df78969f1745`.
Le binaire n'est ni inclus ni publié sur GitHub.

1. **Encodeur SDP natif** : l'appel à `imm_p2p_rtc_sdp_encode` à `0x69ad4` est réel, son implémentation ARM64 est située à `0x73ed8` (3 924 octets).
2. **Médias et structure non figés** : `imm_p2p_rtc_sdp_encode` considère explicitement `audio` (`0x11a8f2`), `video` (`0x11a8fa`) et `imm` (`0x118955`). Le format SDP `m=%s 9 %s%s\r\n` (`0x11a9f3`) et l'en-tête `a=group:BUNDLE%s` / `msid-semantic: WMS %s` (`0x11a99a`) sont **dynamiques** et dépendent de structures natives. Le cas `imm` utilise notamment la forme `application` (`0x11a902`).
3. **Jetons de session** : la fonction native effectue quatre appels à `cJSON_Parse` aux adresses `0x69c40`, `0x69c50`, `0x69c60`, `0x69c70`, sur quatre zones de mémoire de session propres (`[x19+0x1268]`, `[x19+0x1a68]`, `[x19+0x2268]`, `[x19+0x2a68]`). Elle les associe aux clés `token`, `udp_token`, `tcp_token`, `log`. **Chacune est facultative si sa conversion JSON échoue**, comme le montrent les branches `cbz` à `0x69c9c`, `0x69cb4`, `0x69ccc`, `0x69ce4`.
4. **Passage à Java** : le wrapper `api/devId/msg` contient une chaîne JSON sérialisée `msg` ; `ThingP2PSDK.onHttpRequest` la décode avec `JSON.parseObject` et passe son contenu à `ThingApiParams.setPostData`. Notre corps `header/msg` ne doit donc **pas** être encapsulé une seconde fois comme `api/devId/msg`.

Ces preuves ne montrent pas que la C9C extérieure a emprunté ce chemin HTTP spécifique à l'exécution. Elles prouvent seulement sa présence et sa construction native dans l'APK 5.10.12.

## Écarts Python à traiter avant un nouvel essai

| Aspect | SDK Android | Intégration Python | Statut |
|---|---|---|---|
| Source SDP | Encodeur basé sur l'état P2P / liste de médias | `inspect_rtc_media` assemble une seule offre `imm` avec lignes fixes | Équivalence **non démontrée** ; cela ne signifie pas que les lignes divergent toujours |
| `token` | JSON extrait d'une zone propre de l'état P2P | `media.ice_servers` (liste ICE reçue par API RTC) | Provenance différente, identité de valeurs non démontrée |
| `udp_token` | Champ natif optionnel décodé en JSON | Aucun `udp_token` fabriqué par `_media_payload` ; filtre HTTP l'omet | Source/nécessité inconnues ; **ne pas inventer un jeton** |
| `tcp_token` | Champ JSON issu de l'état P2P natif | `media.relay` avec `sessionId` rendez-vous reconstruit | Équivalence non démontrée |
| `log` | JSON d'une zone native | Configuration `p2pConfig.log` | Équivalence non démontrée |
| Appel HTTP | conditionnel à l'état P2P, attente 15 s, puis demande interne | action manuelle directe (même API, version 1.0) | Machine d'état native absente |
| Identité cible | liaison AOSU↔Tuya établie par le SDK Android | candidat unique Tuya, **non prouvé** | Blocage d'identité indépendant |

Important : la correspondance du type média `imm` ou la présence des mêmes attributs ne prouvent pas que l'offre Python est identique octet par octet au vrai SDP natif. Ne pas forcer de champ ou de valeur en se basant sur un modèle d'autres caméras.

## Nouveau code de recherche

- `tools/aosu_c9c_http_sdp_parity_offline.py` accepte **seulement** l'APK locale complète fournie par son propriétaire, extrait l'ELF en mémoire, contrôle son SHA-256 et publie exclusivement des booléens de présence/écart. Aucun secret ou contenu natif n'est renvoyé.
- `tests/test_aosu_c9c_http_sdp_parity_offline.py` emploie un ELF **synthétique** sans code propriétaire. CI : https://github.com/tapion69/smart-aosu-cloud/actions/runs/43585282239.
- Les trois couches de réponse de `do_oem_thing4_session_offer_once` préservent maintenant un `code_erreur_tuya` si le classificateur déjà existant y trouve **uniquement un entier décimal borné à huit caractères**, jamais une chaîne symbolique ou un message brut. Tests hors ligne : https://github.com/tapion69/smart-aosu-cloud/actions/runs/43585477551.
- Le code d'erreur du **dernier** essai n'a pas été conservé ; cette correction n'est **pas rétroactive**, et elle n'autorise pas à relancer une demande juste pour lire le code.

## Suite technique décidée

1. Ne pas envoyer de troisième offre semblable. Garder `main` en `0.8.13-beta44-rc3` ; ne pas toucher au banc stable C5L + deux C9C-H1L ni au PTZ.
2. Reconstituer et vérifier les préconditions du moteur natif : identifiant typé AOSU↔Tuya, création/état des sessions `connect`, formation de la liste média, origine des jetons natifs et choix effectif du chemin HTTP/MQTT.
3. Seule une **correction causale vérifiable** ou une observation contrôlée manquante justifiera ensuite un essai actif sur la caméra. Aucune réussite vidéo ou nouvelle version installable n'est annoncée à ce stade.

**Verdict :** refus explicite réel, source précise encore inconnue ; écarts SDP/jetons/état documentés et outillés, sans recours à de nouvelles manipulations utilisateur.
