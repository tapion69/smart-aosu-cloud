# Smart AOSU — Offre RTC HTTP native : conditions, SDP et rôle de connect_session

**13 novembre 2026 — étude supplémentaire, uniquement branche `experiment/c9c-native-session-contract`.**  
**Aucune nouvelle bêta HA, aucun appel réseau ni commande caméra.**

## Résultat : la négociation Thing-4 est conditionnelle

Cette analyse est réalisée directement sur l'APK complète AOSU 5.10.12 fournie par le propriétaire
(SHA-256 `ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7`),
dans `libThingP2PSDK.so` ARM64, par lecture de sections ELF et désassemblage AArch64.

La routine à partir de l'adresse `0x69968` montre la **véritable préparation d'une demande d'offre RTC HTTP**. Elle est conditionnelle à l'état de la session ; il serait donc incorrect d'ajouter `thing.m.rtc.session.offer_1.0` à chaque ouverture sans reproduire la machine d'états :

1. **État native** : à `0x69998–0x699A8`, lecture de l'état `[x0+0xe58]`, comparaison avec `1`, branche de sortie si cet état correspond. La signification métier exacte de cette valeur n'est pas encore déterminée.
2. **Demande non déjà engagée** : à `0x699D8–0x699DC`, un indicateur `[x19+0xe1c]` dirige le chemin ; si la demande n'a pas commencé, il est positionné à `1` à `0x69A90–0x69A94`.
3. **Délai propre au SDK** : horodatage obtenu par `imm_p2p_misc_get_timestamp_ms`, puis stockage d'un délai de **15 000 ms** dans `[x19+0xe28]` à `0x69A98–0x69AA4`. Ce délai est **distinct** des 9/20 secondes d'attente SDP de notre Python.
4. **Contexte obligatoire** : lecture du pointeur natif `[x20+0x3c8]` et saut si nul (`0x69AA8–0x69AAC`). La présence de l'API en mémoire ne suffit pas à lancer la demande.
5. **Encodage SDP** : appel effectif à `imm_p2p_rtc_sdp_encode` à `0x69AD4`, précédé de la référence à `offer`; le résultat est incorporé dans le message JSON.
6. **Champs de l'offre** : construction de `header` puis `msg` contenant notamment `sessionid`, `trace_id`, `moto_id`, `is_pre`, `p2p_skill`, `sdp`, `token`, `udp_token`, `tcp_token`, `log`. Les données spécifiques proviennent des champs de l'état natif. Aucune valeur de compte ou d'utilisateur n'a été extraite.
7. **Passerelle HTTP** : le JSON comprend l'action `thing.m.rtc.session.offer_1.0` (`0x69D48–0x69D50`), avec l'étiquette `rtc_session_http_req`. Il est sérialisé puis ajouté à une file interne par `bc_msg_queue_push_back` de type **5** (`0x69F50–0x69F5C`). Le circuit JNI/Java démontré dans l'audit précédent prend en charge la requête et le retour.

Il existe d'autres chemins de connexion MQTT/LAN dans le SDK ; les états précis dans lesquels la C9C autonome choisit **ce** chemin n'ont pas été observés à l'exécution. **Ne pas prétendre qu'un appel HTTP seul résout le problème.**

## L'identifiant `connect_session` a aussi une fonction de corrélation

L'ancienne analyse identifiait la génération d'un identifiant aléatoire dans les commandes `connect`, `connect_v2` et `connect_v3`. Le désassemblage actuel complète ce constat :

- dans `imm_p2p_rtc_connect`, l'identifiant est généré à `0x60A88`, puis remis comme argument au gestionnaire à `0x6011C` par l'appel `0x60B14` ;
- le gestionnaire compare la clé fournie avec le champ de la réponse interne `[x23+0x4c]`, via `strncmp(..., 64)` à `0x601A4` ;
- si elle correspond, le résultat de la commande est transféré au demandeur, puis l'entrée d'attente est retirée.

**Conclusion circonscrite : `connect_session` sert notamment de clé pour apparier une commande native à sa réponse.** Ce rôle n'établit **aucune égalité** entre ce champ et le `header.sessionid` de la signalisation MQTT. Il ne faut pas remplacer l'identifiant RTC Python par la chaîne aléatoire native.

## Écart réel avec Home Assistant

Le code `tuya_mqtt_offer._probe` prépare `sigQry(22)`, `offer(302)`, puis attend une SDP answer ; l'intégration ne possède pas le moteur HTTP/RTC à états qui s'arme conditionnellement, encode le SDP, puis attend le résultat de `offer_1.0` via Java.

Le décodage de 18/18 messages lors d'une **session officielle AOSU** en bêta12 confirme une signalisation Tuya exploitable, mais **aucune réponse SDP à notre propre session HA** n'a été obtenue. Les preuves réunies décrivent un mécanisme manquant, **sans établir que la C9C extérieure utilise précisément cette branche**.

## Résultat code et régression

L'outil existant `tools/aosu_c9c_native_connect_session_offline.py` comprend maintenant :
- `native_http_offer_state_facts` : **8 contrôles booléens** sur les branches AArch64, l'armement à 15 secondes, le SDP, le contexte et les jetons de l'offre HTTP ;
- `native_connect_session_correlates_command_reply` : contrôle séparé des instructions de comparaison commande/réponse ;
- validation d'APK SHA-256 avant lecture des adresses, aucune exécution native, aucun identifiant ni secret imprimé.

Le fichier `tests/test_aosu_c9c_native_connect_session_offline.py` ajoute des cas négatifs sur l'état, le délai, le pointeur de contexte et le jeton UDP, **avec un ELF purement synthétique**. Aucun SDK propriétaire n'est envoyé à GitHub Actions.

**CI :** [exécution 43520068810](https://github.com/tapion69/smart-aosu-cloud/actions/runs/43520068810) **réussie**, après consolidation des nouveaux tests.

## Décision : prochaine modification raisonnable

Avant toute implémentation réseau, il reste à obtenir une correspondance démontrable entre
- l'état/type de session C9C (`p2pSpecifiedType=4`) ;
- la branche native qui choisit HTTP `offer_1.0` plutôt que MQTT/LAN ;
- les paramètres que le cloud retourne au SDK et les transitions d'état avant le direct.

Il sera alors possible de concevoir un **adaptateur de session Thing-4 exclusivement C9C autonome**, derrière une activation manuelle et les vérifications d'identité existantes. Ne pas appeler l'API spéculativement : l'identité AOSU SN↔Tuya devId n'est pas encore prouvée, et une ouverture de session modifie un état distant.

**Conservé intégralement :** `main` = `0.8.13-beta43`, toutes les entités, vidéo et PTZ des trois caméras historiques C5L / 2×C9C-H1L. **Pas de bêta44, pas de test utilisateur à répéter.**
