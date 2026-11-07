# Smart AOSU Cloud — 0.8.13-beta5 (essai C9C autonome, correction identification)

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
