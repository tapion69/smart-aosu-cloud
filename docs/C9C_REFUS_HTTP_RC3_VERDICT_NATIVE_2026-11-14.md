# C9C autonome — deuxième refus RTC HTTP après 0.8.13-beta44-rc3

**Audit du 14 novembre 2026, sans émission réseau et sans nouvelle version installable.**

## Résultats observés et confirmés par l'utilisateur

Premier essai `beta44-rc1` : `requete_http_effectuee=true`, `serveur_accepte=false`, `rejet_explicite=true`, `methode_cible=candidat_unique_autorise_manuellement`.

Après suppression de `security_level` de l'en-tête HTTP natif dans `beta44-rc3` :
`requete_http_effectuee=true`, `serveur_accepte=false`, `rejet_explicite=true`, `categorie_refus=indeterminee`, `code_erreur_present=true`, `methode_cible=candidat_unique_autorise_manuellement`.

Le test `beta44-rc2` confirme **seulement** `SN affiché dans AOSU = SN mémorisé par Home Assistant`, **pas** `SN AOSU = devId Tuya`.

**Conclusion ferme :** la suppression du champ HTTP supplémentaire n'a pas levé le refus. Aucun direct, PTZ ou réveil n'a été lancé par le test HTTP. Un nouveau test identique n'est pas justifié.

## 1. L'enveloppe `api/devId/msg` est interne au SDK : ne pas l'envoyer telle quelle

La bibliothèque originale `libThingP2PSDK.so` de l'APK AOSU 5.10.12 fournie par le propriétaire
(SHA-256 `ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7`) crée deux objets distincts :

- **Contenu RTC interne**, à `0x69d00–0x69d30`, où `header` et `msg` sont sérialisés par `cJSON_PrintUnformatted`. L'en-tête porte huit champs dans ce constructeur HTTP natif. `msg` contient un SDP produit par `imm_p2p_rtc_sdp_encode` et des champs `token`, `udp_token`, `tcp_token`, `log` lorsqu'ils sont présents.
- **Enveloppe de passage natif → Java**, à `0x69d3c–0x69db0`, portant exactement les clés `api`, `devId`, `msg`. Les chaînes sont ancrées respectivement à `0x118a38`, `0x116971`, `0x11d0da` ; `api` vaut `thing.m.rtc.session.offer_1.0`. `msg` est ici une **chaîne** contenant le JSON sérialisé précédent.

Dans `classes6.dex`, `ThingP2PSDK.onHttpRequest` (index méthode `13152`) reçoit trois paramètres Java. Son bytecode :

- recherche le séparateur `_` et sépare **action** et **version** (instructions `60–86`) ;
- effectue `JSON.parseObject` sur l'argument de contenu (instruction `100`) ;
- transmet l'objet obtenu à `ThingApiParams.setPostData` (instruction `104`), puis à `Business.asyncRequest` (instruction `125`).

Par conséquent, le `form_data={"header": ...,"msg": ...}` de `do_oem_thing4_session_offer_once` correspond **au contenu `postData` du chemin Java**. Il serait incorrect de transmettre `api/devId/msg` comme corps HTTP supplémentaire sur la seule base du constructeur natif : ce wrapper est consommé dans le pont natif → Java.

## 2. La piste d'un proxy HTTP OEM reste théorique

La méthode Java `onHttpRequest` permet un chemin **facultatif** `IHttpProxy.onHttpRequest` (instruction `46`) lorsque le SDK dispose d'un proxy configuré ; sinon elle utilise `Business.asyncRequest`.

Un contrôle statique de **17 DEX** de l'APK AOSU complète n'a trouvé que deux invocations de `setHttpProxy`, dans des méthodes du SDK qui **implémentent ou délèguent elles-mêmes** ce setter. Aucune invocation directe de ce setter depuis les classes applicatives AOSU n'a été repérée. Cela rend peu probable l'hypothèse qu'un proxy AOSU personnalisé ait été simplement oublié dans notre passerelle.

**Limite :** ce constat statique n'exclut pas une configuration indirecte (réflexion, chargement dynamique, composant non inspecté). Il ne faut pas déduire qu'un proxy est absolument impossible.

## 3. Le contrat SDP n'est pas encore reproduit à l'identique

- Le SDK OEM appelle `imm_p2p_rtc_sdp_encode` avec **l'état RTC natif courant** et le type `offer` à `0x69ac4–0x69ad4`. La fonction native construit des attributs SDP conditionnels selon cet état.
- Notre `tuya_media_bootstrap.inspect_rtc_media` assemble une **offre SDP manuelle** (quelques attributs AES/KCP/ICE) à partir du schéma JSON reçu de `thing.m.rtc.config.get` et d'un client Python de référence non AOSU.
- La similarité de champs `AES/KCP`, `ice-ufrag`, `ice-pwd` et `a=aes-key` ne démontre pas **l'équivalence exacte** des SDP ni des jetons de session natifs.
- Le chemin natif est activé **conditionnellement** (état et contrôle de requête déjà en cours, délai de 15 secondes), alors que le test HTTP Python crée une offre hors de cette machine d'états.

**Conclusion technique :** l'enveloppe HTTP ne constitue plus une différence démontrée ; la provenance de l'identité Tuya, le SDP/jetons natifs et les conditions d'exécution de l'API restent des divergences ou inconnues plausibles. On ne peut pas choisir la cause sans code de refus qualifié ou équivalence native plus poussée.

## 4. Pourquoi le refus reste `indeterminee`

`_safe_server_refusal` détecte la présence d'un code et essaie de classifier **des mots-clés de l'erreur**, mais ne connaît pas toutes les familles Tuya. Le service HTTP filtre ensuite le résultat avant de le rendre à Home Assistant. `code_erreur_present=true` ne suffit pas à connaître la signification du code et **aucun code numérique brut n'a été conservé dans la réponse communiquée**. Il ne peut donc pas être reconstitué à partir de ce diagnostic.

**Ne pas** traduire le refus en « mauvais SN », « problème de signature » ou « mauvaise permission » sans preuve supplémentaire.

## 5. Décision et prochaine étape ciblée

1. **Aucune nouvelle exécution HTTP**, MQTT, réveil ou PTZ à demander maintenant.
2. Ne pas toucher à `main` **`0.8.13-beta44-rc3`** ni à la vidéo/PTZ historiques C5L / C9C-H1L.
3. Sur branche de recherche, vérifier le contenu / la provenance du SDP natif, les jetons RTC et la condition de branche `HTTP offer_1.0` versus 302 MQTT pour **Thing-4**.
4. En parallèle, chercher une **correspondance typée exacte AOSU SN ↔ Tuya uuid/cpUuid/devId** dans les structures autorisées, sans assimiler « unique candidat Tuya » à une preuve.
5. Préparer tout essai actif ultérieur seulement si un changement causal concret est identifié. Le serveur peut refuser une offre pour plusieurs raisons non distinguables ici.

**Verdict : refus réel et reproductible, pas de diagnostic causal définitif.** 
