# Smart AOSU Cloud — 0.8.13-beta21 (essai C9C autonome, correction identification)

> **EXPÉRIMENTAL — intégration indépendante et non officielle, non validée sur une seconde installation.**
>
> La vidéo et le PTZ ont été confirmés en 0.8.10 sur le banc de développement (1× C5L et 2× C9C3CA11 derrière H1L). Cette nouvelle bêta n'a pas été testée physiquement ; ne l'utilisez pas comme unique système de sécurité.

## Installation (test externe)

L'intégration peut être téléchargée depuis son dépôt source. Elle ne distribue **aucun APK ni ressource propriétaire**. Sur un Home Assistant propre :

1. Installer `custom_components/smart_aosu_cloud/` depuis le dépôt (Marketplace/HACS après publication d'une version utilisable, ou copie manuelle du code pour des tests de développement).
2. Redémarrer Home Assistant, puis **Paramètres → Appareils et services → Ajouter une intégration → Smart AOSU Cloud**.
3. Choisir directement depuis son ordinateur les deux fichiers personnels de compatibilité AOSU 5.10.12 :
   - `Aosu_5.10.12_21839.apks.apk` (APK Lite ~1,69 Mo)
   - `Aosu_5.10.12_OEM_resources.zip` (~86,8 Ko)
4. Home Assistant valide le contenu, crée automatiquement `/config/smart_aosu_cloud/` et y range les deux fichiers sans intervention dans le système de fichiers.
5. Saisir l'**e-mail** et le **mot de passe AOSU** ; indiquer l'IP privée de la station H1L si applicable (facultatif).
6. Vérifier d'abord la découverte des entités, puis la vidéo et le PTZ. Le profil Android fictif est généré automatiquement. Son acceptation par les serveurs AOSU n'a pas encore été confirmée sur une installation externe.

Les ressources propriétaires sont importées uniquement depuis l'ordinateur du testeur vers **son Home Assistant**, pas vers GitHub ni vers un serveur tiers de Smart AOSU. Les APK ne sont pas installées sur le téléphone Android.

**Limitations :** les fichiers doivent correspondre précisément au build AOSU 5.10.12 étudié ; une autre version est rejetée. Les cartes Lovelace doivent encore être ajoutées en suivant [docs/CARTES_LOVELACE.md](docs/CARTES_LOVELACE.md). Voir [docs/INSTALLATION_TEST.md](docs/INSTALLATION_TEST.md) pour le détail et [docs/PLAN_TEST.md](docs/PLAN_TEST.md) pour le test physique.

**Confidentialité :** ne publiez jamais APK, OEM ZIP, `profile.json`, mot de passe, jeton, IP, MAC, numéro de série, captures ou logs non expurgés. Une APK modifiée reste soumise aux droits de son éditeur ; chaque testeur doit utiliser des copies qu'il est autorisé à utiliser. Le code original est proposé sous PolyForm Strict 1.0.0, sous réserve des droits de tiers.

## C9C autonome — essai vidéo expérimental (0.8.13-beta5)

Après installation sur un compte ne contenant qu'une C9C autonome et sans base H1L, ajouter la carte décrite dans `docs/CARTES_LOVELACE.md`. La première bêta échouait parfois avant la négociation RTC (`rtc_non_lance_c9c_non_identifiee`) lorsque l'inventaire Tuya contenait plusieurs appareils, dont une seule caméra. Cette version corrige cette condition et affiche les comptes d'appareils/caméras anonymisés si la sélection échoue.

Ne pas relancer plusieurs fois sans examiner le statut. Les commandes PTZ sont désactivées pour cette caméra tant que la vidéo et le STOP ne sont pas validés.

## 0.8.13-beta5 : test C9C autonome sans catégorie Tuya

Avec une seule C9C autonome détectée dans AOSU, un seul appareil dans l’inventaire Tuya peut être essayé sans catégorie caméra reconnue, seulement après action manuelle et si Tuya n’annonce pas explicitement une catégorie non vidéo. Cette sélection reste **incertaine** : pas de PTZ et pas d’essai automatique. Consulter le diagnostic `statut_direct_c5l` après un seul essai.

## 0.8.13-beta5 : clarification du diagnostic MQTT C9C

La négociation MQTT émet d'abord une interrogation sigQry (protocole 22), puis une offre SDP (protocole 302). Une réponse à l'interrogation ne constitue pas une réponse SDP vidéo : les deux familles sont désormais comptées distinctement. Aucun changement de protocole n'est introduit. Le modèle C9C autonome reste expérimental et sans PTZ.

## Beta 0.8.13-beta5 — diagnostic de correspondance C9C autonome

La carte C9C autonome propose **Vérifier identité**. Le bouton lit un inventaire Tuya en mémoire, ou l'actualise manuellement si besoin, puis compare exclusivement en RAM les numéros de série AOSU et les identifiants coopUUID avec les champs Tuya connus. Il ne transmet jamais ces identifiants dans le résultat. La sélection d'un seul appareil Tuya sans catégorie vidéo **ne prouve pas** son identité. L'appel n'envoie ni offre SDP, ni message MQTT, ni commande caméra ou PTZ. Le protocole de la C5L et les contrôleurs H1L restent inchangés.

## 0.8.13-beta6 : lecture seule du routage C9C

Le bouton **Vérifier identité** présente aussi les informations déjà filtrées du dernier inventaire AOSU : fournisseur `sdkProvider`, type P2P, branche PTZ Gz/Ty et présence de référence Tuya. Le type de transport vidéo réel reste **non démontré**. Une comparaison exacte supplémentaire teste localement si le numéro de série AOSU est identique à l'identifiant Tuya. **Aucune sélection automatique n'est modifiée** ; aucun réseau, vidéo, PTZ ou secret n'est utilisé par cet ajout.

## 0.8.13-beta7 : fiche AOSU détaillée de la C9C autonome

Bouton manuel **Fiche AOSU** sur la carte C9C autonome. Une seule requête HTTPS autorisée par heure vers `/v1/dev/getInfoBySn`, API déjà utilisée par le diagnostic C5L. Compare exclusivement en mémoire les champs d'identité à l'inventaire Tuya déjà disponible, sans afficher de SN, UID, clé locale ni jeton. Les indices de fournisseur P2P et de présence de références ne prouvent pas que la vidéo fonctionne. Aucune nouvelle offre vidéo ni PTZ. Une erreur ou un refus HTTP n'est pas relancé automatiquement.

## 0.8.13-beta8 — diagnostic RTC C9C autonome, sans vidéo

Le PCAPdroid fourni pour la C9C autonome montre une réception distante par TURN/UDP et KCP, sans prouver le protocole de signalisation dans le TLS. Le bouton **Examiner RTC** fait une lecture volontaire et limitée de la configuration RTC pour l'unique candidat Tuya (qui reste **non confirmé**). Il affiche uniquement la présence des paramètres ICE, TURN, relais TCP/UDP, `moto_id` et la version `pv` si reconnue (2.2/2.3). Aucun identifiant, URL, clé, SDP ni contenu privé n'est retourné, enregistré ou publié. L'action peut demander une authentification au service Tuya. Elle **n'envoie aucune offre MQTT, ne lance aucune vidéo ni PTZ**. Un résultat RTC positif n'établit pas que la cible Tuya est bien la C9C. Les contrôleurs C5L/H1L sont inchangés.

## 0.8.13-beta9 — essai moto_id sur C9C autonome

D'après la documentation officielle Tuya WebRTC, `moto_id` est un champ facultatif de signalisation, renvoyé par la configuration lorsqu'il est pris en charge. La 0.8.13-beta8 indiquait un `moto_id` présent quelque part dans le RTC mais le moteur d'essai envoyait un champ vide dans l'offre.

En bêta9, **uniquement après un clic sur « Essayer la vidéo » pour une unique C9C autonome**, l'intégration recherche `moto_id` dans des champs prédéfinis de la *même* réponse RTC fraîche ; s'il existe une valeur unique et valide, elle est mise dans l'offre MQTT et les messages de session associés (candidate/disconnect). Si la valeur est absente ou ambiguë, elle reste vide. Le rapport affiche seulement la source anonymisée et un booléen, jamais le `moto_id` lui-même. Les contrôleurs vidéo/PTZ des C5L et H1L restent inchangés.

**Important :** la correspondance AOSU/Tuya de la C9C autonome reste non prouvée ; l'acceptation de la configuration RTC et une PUBACK MQTT ne prouvent pas la réception de l'offre par la caméra. L'essai doit être manuel, une seule tentative, sans PTZ.

## 0.8.13-beta10 — écoute MQTT passive pendant le direct officiel

La C9C autonome n'a toujours répondu à aucune offre SDP depuis HA, même avec le moto_id fourni par RTC. Un bouton **Observer MQTT** teste uniquement les abonnements aux canaux existants `smart/mb/in` et `/av/u`, pendant 20 secondes **sans aucune publication**, vidéo ou PTZ. Ouvrir le direct officiel dans AOSU sur le téléphone pendant l'observation. Seuls les statuts d'abonnement et les nombres de messages sont affichés. Aucun contenu chiffré, identifiant, jeton ou métadonnée privée ne quitte la mémoire. Cette observation ne prouve pas une correspondance de caméra et zéro message n'exclut pas d'autres chemins de signalisation. Cible : un seul modèle C9C autonome sans station. Pour éviter une interruption du direct HA, l'écoute refuse de démarrer si un direct HA est déjà actif.

Le compte Tuya peut être authentifié et l'inventaire/RTC lu, mais aucune commande n'est envoyée aux caméras. Garder en tête les limitations d'inventaire (30 min), d'RTC (5 min) et d'écoute (10 min). La vidéo/PTZ des caméras déjà validées n'est pas modifiée.

## 0.8.13-beta11 — classifier les messages MQTT C9C reçus

Le test externe a obtenu 19 messages sur le sujet `smart/mb/in/<appareil>`, aucun sur `/av/u/<uid>`, pendant le direct officiel AOSU. Cela montre une activité MQTT mais **ne prouve pas** qu'il s'agit de messages vidéo.

Cette version conserve le bouton **Observer MQTT**, la fenêtre de 20 secondes et les sujets existants. Elle vérifie **uniquement en mémoire** le format chiffré `2.2`, la possibilité de déchiffrer avec la clé locale déjà disponible, les protocoles `22`/`302`, et les types `offer`/`answer`/`candidate`/`disconnect` ainsi que les correspondances d'identifiants exacts. Les sorties ne contiennent **que des compteurs** : aucun identifiant, clé, nom, IP, sujet réel, trame, SDP ou contenu de message n'est enregistré ou retourné. Le déchiffrement est une observation ; il ne modifie aucun paquet.

La C9C demeure une cible expérimentale non confirmée. Aucun changement aux contrôleurs vidéo C5L, C9/H1L, ni aux commandes PTZ. Une trame non déchiffrable n'établit ni l'absence de vidéo ni une mauvaise identité : le format ou la clé peuvent être différents.

## 0.8.13-beta12 — comparer la session MQTT officielle à l'offre Home Assistant

Une observation sur la C9C autonome a montré 18/18 publications chiffrées au format 2.2 déchiffrables, dont cinq du protocole 302 (une `answer`, quatre `candidate`), toutes cinq émises par l'appareil Tuya sélectionné. Ces observations ne prouvent toutefois pas que l'offre Home Assistant est acceptée : elles sont issues d'une session lancée par l'application officielle.

Le bouton manuel **Observer MQTT** conserve le fonctionnement passif de la bêta11, et ajoute des compteurs anonymes sur les champs `from`/`to`, `path`, présence de `sessionid` et `moto_id`, SDP et codec AES/KCP dans les réponses, candidats ICE. Aucun contenu, identifiant, SDP, clé ni adresse n'est enregistré, retourné ou publié. Le test s'effectue en ouvrant le direct officiel sur le téléphone pendant l'écoute. Les moteurs vidéo/PTZ C5L/H1L et l'offre C9C restent strictement inchangés.

## 0.8.13-beta13 — test RTC IPC-v4 en lecture seule pour C9C autonome

Le direct officiel a produit 18 trames MQTT déchiffrables, dont un `answer` SDP AES/KCP et des `candidate` (protocole 302), émises par la cible Tuya et dirigées vers l'utilisateur. Le moteur de direct expérimental n'obtient toujours aucune réponse SDP. Il utilise actuellement la méthode RTC `thing.m.rtc.config.get`, alors que des clients IPC indépendants utilisent `m.ipc.v4.rtc.config.get`.

Ajout d'un bouton **Comparer RTC IPC** : une lecture expresse de `m.ipc.v4.rtc.config.get` sur la C9C autonome **sans MQTT, sans offre, sans vidéo ni PTZ**. La réponse n'est pas conservée : seuls les drapeaux de validité/présence ICE, TURN, relais TCP/UDP, clé locale, session et `moto_id` sont retournés. Les limitations d'inventaire/login/RTC restent actives. Aucun changement de méthode RTC dans le direct, ni dans la C5L ou le H1L. L'identité AOSU/Tuya reste non définitivement confirmée, malgré la signalisation officielle observée.

## 0.8.13-beta14 — correction de la lecture RTC IPC-v4

Le bouton **Comparer RTC IPC** de la beta13 renvoyait `erreur_api_tuya`, non pas parce que la C9C ou Tuya avait rejeté l'appel, mais parce que notre garde-fou `do_oem_read` refusait localement l'action `m.ipc.v4.rtc.config.get` absente de sa liste autorisée. **Aucune requête réseau RTC-v4 n'avait pu être émise.**

Cette correction ajoute exclusivement cette lecture (`v=1.0`, `{"devId":"..."}`) à la liste autorisée ; seuls les diagnostics manuels C9C l'appellent, jamais le direct C5L/H1L, ni le PTZ. L'éventuel nouveau refus affiche uniquement une origine déterminée parmi `validation_locale`, `reponse_http_invalide`, `reseau_ou_dechiffrement`, `refus_du_serveur` ou `erreur_inconnue`. Aucun texte brut de réponse, code inconnu ou identifiant privé n'est retourné.

**Test** : mettre à jour, redémarrer et cliquer **Comparer RTC IPC**, après expiration de la protection de 5 minutes. Ne pas lancer le direct depuis Home Assistant pendant ce test.

## 0.8.13-beta15 — essai vidéo manuel RTC IPC-v4 pour la C9C autonome

Sur une installation externe, `m.ipc.v4.rtc.config.get` a répondu positivement : configuration média complète, session, ICE/TURN et relais TCP. Les observations MQTT officielles montraient une réponse SDP AES/KCP, mais notre direct Home Assistant n'en recevait pas via l'ancienne méthode `thing.m.rtc.config.get`.

**Uniquement** lorsque l'utilisateur appuie sur **Essayer la vidéo** pour une unique C9C autonome sans station, le moteur demande désormais sa configuration RTC avec `m.ipc.v4.rtc.config.get` (API v1.0 déjà autorisée en bêta14). La suite MQTT/SDP/ICE/KCP et le `moto_id` sont inchangés, afin d'isoler cette modification. Les chemins C5L et H1L conservent leur RTC antérieur.

Le diagnostic `statut_direct_c5l` contient un nouveau champ **`dernier_resultat.rtc_api_source`** (`ipc_v4` ou `thing_rtc`) sans identité privée. La carte affiche également cette méthode après la fin de l'essai. Le PTZ C9C reste désactivé.

**Attention :** obtenir la configuration RTC ne garantit pas l'arrivée d'une SDP ni d'une vidéo ; le relais TURN/UDP/KCP reste un chantier distinct. Une seule tentative manuelle, puis inspection du diagnostic, sans répétition automatique. Aucun compte, token, PCAP, APK ou configuration d'installation n'est distribué.

## 0.8.13-beta16 — observation de l'offre MQTT officielle (lecture seule)

Le direct C9C autonome ne reçoit toujours pas de SDP, même avec RTC IPC-v4 et `moto_id`. Les sessions vidéo de l'application officielle donnent bien des messages de réponse MQTT `302` déchiffrables dans `smart/mb/in`, mais pas encore le contenu structurel des offres initiales.

Le bouton existant **Observer MQTT** tente maintenant de s'abonner, en plus des deux canaux précédents, à `smart/mb/out/<appareil>` (canal sortant). Cet abonnement peut être interdit par le broker : le résultat le précise et **les deux abonnements précédents continuent normalement**. Pendant le direct officiel, la sonde classe les seules offres `302` dans la mémoire volatile (SDP AES/KCP, `path`, `sessionid`, `moto_id`, `trace_id`, `p2p_skill`, `security_level`, tokens, préconnexion), sans exposer aucune valeur. Les offres retained MQTT sont ignorées.

La sonde ne publie aucun MQTT PUBLISH, n'envoie aucune offre, ne démarre ni session vidéo ni PTZ et ne conserve ni trame, ni clé, ni adresse, ni identifiant. Zéro offre observée ne prouve pas l'absence d'offre : le serveur peut refuser ou ne pas retransmettre le canal sortant. Aucun changement à la vidéo C5L/H1L ni au moteur C9C ; seule la sonde passive est étendue.

## 0.8.13-beta17 — expliquer les messages reçus après le réveil officiel

Après ouverture puis fermeture du direct AOSU, l'essai C9C dans Home Assistant a reçu **7** publications MQTT et **4** requêtes STUN, mais **0 réponse SDP à la session HA**. Une publication était au protocole 302 avec un identifiant de session différent ; six avaient un protocole autre que 22/302. Les requêtes STUN ne prouvent pas une acceptation de l'offre HA : elles peuvent venir de la session officielle précédente.

La bêta17 ne modifie aucune requête RTC, offre MQTT, ICE, décodage ou PTZ. Elle classe **uniquement pour l'essai manuel C9C autonome** les six protocoles non reconnus par plages numériques et les messages 302 de session différente par types `answer`, `candidate`, `disconnect` et présence d'un SDP. Des correspondances exactes avec les identifiants de l'appareil et du compte sont comptées en RAM sans jamais retourner les identifiants. Cela permettra de savoir si la SDP reçue après le réveil appartenait à l'ancienne session AOSU.

Aucune nouvelle tentative automatique ni nouvelle commande. Un seul essai manuel après mise à jour, sans simultanéité avec le direct officiel, suffit au diagnostic. **Les contrôleurs C5L/H1L restent inchangés.**

## 0.8.13-beta18 — vérifier passivement le DP 149 de la C9C autonome

Le direct de la C9C solaire autonome demeure bloqué avant réponse SDP, même via RTC IPC-v4. La documentation Tuya décrit un mécanisme de réveil `wirelessWake(devId)` pour les caméras basse consommation, et un état de veille `DP 149 / wireless_awake`. **Cette fonction SDK n'est pas une action OEM Python confirmée : aucun réveil n'est envoyé.**

Le bouton existant **Observer MQTT** classe maintenant, en plus de la vidéo, les éventuelles déclarations DP 149 dans l'inventaire Tuya chargé pour l'unique C9C autonome, et les rapports DP 149 déchiffrés dans le canal MQTT de l'appareil pendant les 20 secondes d'observation. L'écran n'affiche que présence, indices basse consommation explicitement typés booléens, et nombres de messages `true`, `false` ou non booléens. Aucune valeur privée ni message brut. Un résultat absent est **inconnu**, et la convention exacte `true`/veille n'est pas présumée ; elle doit être vérifiée sur ce modèle et son firmware.

Pour tester : mettre à jour, redémarrer HA, cliquer **Observer MQTT**, puis ouvrir le direct dans AOSU officiel durant l'observation. Envoyer uniquement le texte du diagnostic. **Aucun changement des offres MQTT, ICE/KCP, PTZ ou caméras C5L/H1L.** Les fréquences d'authentification et d'observation existantes sont maintenues.

## 0.8.13-beta19 — réveil expérimental manuel de C9C autonome

L'observation de la bêta18 a trouvé un rapport MQTT `DP149 wireless_awake=true` pendant un direct AOSU, compatible avec un réveil selon la [documentation Tuya des caméras basse consommation](https://developer.tuya.com/en/docs/iot-device-dev/tuyaos-package-ipc-device?id=Kcuwpao8ihq38). Le SDK officiel expose `wirelessWake(devId)`, mais ne documente pas publiquement son équivalent sous forme d'appel OEM Python. Une [intégration Home Assistant indépendante](https://github.com/JustDauren/tuya-peephole-integration) sous licence MIT emploie le topic `m/w/<deviceId>` et un CRC32 big-endian de la clé locale pour solliciter un réveil ; cette méthode n'est **pas confirmée pour les caméras AOSU C9C**.

Un nouveau bouton **Tester le réveil** est proposé uniquement sur la carte expérimentale C9C autonome. Clic volontaire = **une commande MQTT réelle** sur la session TLS déjà gérée par notre intégration, suivie de 25 s d'écoute des rapports DP149, sans démarrage de vidéo ni PTZ. QoS1 PUBACK confirme seulement la réception du broker, **pas celle de la caméra**. Si un DP149 `true` apparaît, il signale une activité compatible avec un réveil, mais un autre client peut l'avoir provoquée. Ne pas ouvrir AOSU pendant le test pour éviter toute interférence.

Le mode exige la cible C9C unique, une session utilisateur et une configuration RTC IPC-v4 valides, sans direct HA déjà lancé. Il ne réessaie pas automatiquement et applique un cooldown de 10 minutes par client. Les champs privés, CRC32, identité et paquets ne sont ni affichés ni enregistrés. **Les contrôleurs vidéo/PTZ C5L et H1L restent inchangés**, de même que la négociation vidéo expérimentale C9C.

### Test

Mettre à jour, redémarrer HA, ne pas ouvrir la vidéo AOSU et cliquer **Tester le réveil** une fois. Envoyer uniquement le statut expurgé. N'effectuer aucun test vidéo en parallèle.

## 0.8.13-beta20 — réveil et offre vidéo en une seule opération

La C9C autonome a répondu par un état `DP149=true` à la commande de réveil expérimentale du bouton séparé en bêta19, mais l'essai vidéo lancé manuellement ensuite n'a toujours pas reçu de SDP. Ce signal de réveil n'est pas une preuve absolue que la caméra acceptera le direct.

Nouveau bouton manuel **Réveil + vidéo** (distinct de **Essayer la vidéo**). Il demande une seule configuration RTC IPC-v4, envoie **une** commande MQTT de réveil, attend la confirmation technique `PUBACK` et l'observation `DP149=true` (maximum 25 secondes), puis, seulement si les deux signaux sont présents, utilise **la même configuration RTC** pour envoyer l'offre vidéo. Le délai entre la réception du réveil et l'offre est réduit aux opérations réseau nécessaires. Si l'état réveillé n'est pas observé, aucune offre vidéo n'est envoyée : le motif est indiqué dans `dernier_resultat.reveil_et_video`. Le bouton de réveil précédent et sa protection de 10 minutes restent en vigueur ; aucune répétition automatique n'est programmée.

Ceci est un essai P2P actif, **réservé au clic explicite sur la carte C9C autonome**, et non une automatisation. L'ancienne commande « Essayer la vidéo » conserve son comportement et aucun contrôleur C5L/H1L, PTZ, codec ou transport n'a été modifié. Le direct peut échouer malgré un réveil confirmé si l'offre MQTT est incompatible. Aucune clé, adresse, identifiant, SDP ni message brut n'est affiché ou publié dans le dépôt.

**Test** : attendre au minimum 10 minutes depuis la dernière commande de réveil, mettre à jour et redémarrer Home Assistant. Ne pas ouvrir l'application AOSU, cliquer une seule fois sur **Réveil + vidéo**, attendre la fin de la session, puis consulter `dernier_resultat.reveil_et_video` et `dernier_resultat.signalisation_b89`.


## 0.8.13-beta21 — même connexion MQTT pour le réveil et la vidéo

Le bouton **Réveil + vidéo** sur une unique C9C autonome conserve la même
connexion MQTT/TLS authentifiée, sans nouvelle connexion entre le réveil et
la publication de l'offre SDP. Après PUBACK du réveil et DP149=true,
une seule offre vidéo est envoyée dans la même session. Si le réveil
n'est pas confirmé sous 25 secondes, aucune offre n'est envoyée.
Une tentative manuelle et dix minutes de pause entre deux réveils restent
obligatoires. La C5L et les C9/H1L ne sont pas modifiées.

Le diagnostic distingue réveil, PUBACK du réveil, envoi et PUBACK de l'offre
vidéo, ainsi que les délais de réveil et de publication après confirmation.
Un PUBACK ne prouve jamais que la caméra a accepté l'offre SDP.
Cette bêta nécessite encore un essai réel sur la caméra externe.
