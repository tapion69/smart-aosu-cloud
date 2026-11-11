# Smart AOSU beta38 — comparer la configuration du SDK Android à IPC-v4

Date : 11 novembre 2026. Uniquement C9C autonome sans H1L.

## Retour beta37

Le test réel **Préparation SDK** a confirmé dans le compte Tuya :
- Fiche Tuya acceptée, identifiant Tuya cohérent dans la fiche,
  `skills.p2pType=4` (Thing), clé locale présente.
- `m.ipc.v4.rtc.config.get` accepté ; `p2pConfig`,
  `p2pPolicy`, `sessionTid`, `sessionId` présents.
- `p2pId` et `clientTid` non retrouvés par le parseur dans la
  réponse IPC-v4 ; `productBean` et la catégorie `sp`
  ne sont pas présents dans la fiche Tuya interrogée.
- Aucune association précise AOSU ↔ Tuya ; aucune vidéo prouvée.

## Nouvelle preuve issue de la vraie APK AOSU 5.10.12

Analyse statique locale du `classes6.dex` fourni par
l'utilisateur (aucun fichier propriétaire public) :

- La méthode `ThingSmartCameraP2PSync.getClientTid`
  appelle `System.currentTimeMillis` et construit une
  chaîne avec `StringBuilder.append`. Le `clientTid`
  peut donc être créé **localement**, son absence dans la
  réponse réseau IPC-v4 n'étant pas une erreur en soi.
- Le chemin `ThingSmartCameraP2PSync.requestCameraConfig`
  appelle la variante `CameraBusiness.requestCameraInfo`
  qui effectue `thing.m.rtc.config.get` avec `devId`.
- Une autre variante `requestCameraInfo` du même SDK porte
  l'action `thing.m.rtc.session.init`, potentiellement
  initialisatrice de session. **Ce nouveau test ne l'appelle pas**.
- Le SDK consomme `CameraInfoBean.getP2pId` dans
  `processCameraInfo`. Cela ne prouve pas que le
  `p2pId` soit requis pour un fournisseur Thing (=4) :
  le bytecode contient aussi une gestion d'erreur TUTK
  en cas de P2P ID nul.

## Nouveau diagnostic beta38

Le bouton existant **Préparation SDK** est réutilisé, sans nouveau
bouton dans l'interface :

1. Réutilise l'inventaire Tuya du compte sous les limites de
   fréquence existantes, en exigeant une C9C autonome unique.
2. Lit `thing.m.device.get` comme précédemment.
3. Lit `m.ipc.v4.rtc.config.get` comme précédemment.
4. Lit **une seule fois** `thing.m.rtc.config.get`, API
   effectivement utilisée par la méthode du SDK Android.
5. Compare **les présences de champs**, sans conserver ni
   exporter leurs valeurs :
   `p2pId`, `sessionTid`, `p2pPolicy`,
   `p2pSpecifiedType`, `p2pConfig` (objet/chaîne/absent),
   `sessionId`, `password`, `token`, `skill`.
6. En cas d'échec de l'API classique, l'indicateur `acceptee`
   devient faux et les autres drapeaux sont masqués.
7. La comparaison ne déchiffre pas les chaînes de configuration.
   Elle ne crée aucune session, n'envoie aucune offre MQTT,
   ne réveille pas la caméra, ne réalise aucun PTZ et
   n'interrompt pas les vidéos des trois caméras historiques.

### Prochain test utilisateur

- Installer `0.8.13-beta38` depuis `main`,
  redémarrer Home Assistant, puis `Ctrl+F5`.
- Cliquer **une fois** sur **Préparation SDK** de la
  C9C autonome, **sans utiliser Fiche AOSU/Fiche Tuya**.
- Transmettre le rapport anonymisé complet, surtout les lignes
  `RTC IPC-v4` et `RTC SDK classique` avec les champs
  `p2pId`, `sessionTid`, `p2pPolicy` et
  le format `p2pConfig`.
- Respecter les limitations des requêtes Tuya si le test
  retourne une erreur de cadence ou de session.

### Interprétation

- `p2pId` présent dans le classique mais absent d'IPC-v4 :
  différence vérifiée entre les deux réponses cloud.
  C'est un indice pour ajuster le choix de configuration.
- `p2pId` absent des deux : il ne faut pas le fabriquer.
  Examiner si la branche SDK Thing 4 peut s'en passer,
  ou si un autre parcours légitime l'obtient.
- `p2pConfig` différent dans les deux endpoints :
  ne pas supposer leur interchangeabilité ou décoder
  des métadonnées privées au hasard.
- `clientTid` ne sera pas demandé au cloud : le SDK
  Android le construit localement.
- Aucune présence de champ n'établit à elle seule une
  identification formelle AOSU↔Tuya ni une vidéo.

Les tests CI sont hors réseau, sur fixtures synthétiques.
Le moteur vidéo, la station H1L, les entités et le PTZ restent
inchangés. Ne pas ajouter `thing.m.rtc.session.init` ni
une offre réelle sans protocole justifié et vérification de cible.
