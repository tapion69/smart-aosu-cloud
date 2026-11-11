# Smart AOSU Cloud — bêta40 : vrai constructeur SDP confronté à Thing-4

Date : 11 novembre 2026. Recherche sur la C9C autonome, **pas**
sur les deux C9C3CA11 de la station H1L ni la C5L.

## Résultat réel de la bêta39

La carte « Préparation SDK » montre :
- Fiche Tuya acceptée avec identifiant Tuya concordant,
  `skills.p2pType=4`, clé locale présente.
- Deux configurations RTC acceptées (IPC-v4 et SDK classique).
- Pour les **deux** : `p2pConfig` sous forme d'objet,
  `sessionTid`, `p2pPolicy`, et `id` à la racine
  de la fiche RTC présents ; `p2pId` absent.
- Pour les **deux** : `p2pSpecifiedType = 4` et
  branche Thing-4 cohérente selon les champs présents.
- Identité AOSU ↔ Tuya, acceptation d'une offre MQTT
  et vidéo **toujours non démontrées**.

Ce résultat montre que les paramètres de la branche 4 existent.
Il **ne** valide **pas** les octets de signalisation ou la cible.

## Analyse hors ligne du véritable APK AOSU 5.10.12

Dans `classes6.dex`, méthode
`ThingSmartCameraP2PSync.processCameraInfo` :
- La branche de `getP2pSpecifiedType == 4` appelle
  `CameraInfoBean.getId` → `ConfigCameraBean.setP2pId`.
- Elle appelle `CameraInfoBean.getP2PConfigStr` →
  `ConfigCameraBean.setToken`, ainsi que
  `CameraInfoBean.getSkill` → `ConfigCameraBean.setSkill`.
- `CameraInfoBean.getP2PConfigStr` appelle
  `com.alibaba.fastjson.JSON.toJSONString` sur le
  **champ `p2pConfig`**. Cette sérialisation native ne
  peut pas être considérée comme équivalente à une chaîne
  JSON construite arbitrairement en Python.
- Le chemin renseigne aussi clé locale, mot de passe,
  `devId`, identifiant local, trace de client et
  données de configuration avant `createDeviceIPC`.
- Le SDK crée ensuite un objet caméra natif. Le code
  Home Assistant actuel **ne possède pas** d'équivalent
  démontré de `ThingIPCSdk` / `ICameraP2P.createDevice`.

En revanche, la voie Python actuelle :
- consomme `m.ipc.v4.rtc.config.get` pour une C9C ;
- extrait directement les paramètres AES/KCP,
  construit un SDP puis une trame MQTT 2.2 ;
- a obtenu PUBACK sur un essai précédent, **sans SDP answer**.

Ces différences justifient de ne plus remplacer aveuglément
des identifiants ou de multiplier les essais MQTT.

## Changement bêta40

Le bouton existant « Préparation SDK » fait
**exactement les mêmes trois lectures** qu'en bêta39 :
`thing.m.device.get`, `m.ipc.v4.rtc.config.get` et
`thing.m.rtc.config.get`, sous les limites d'accès
existantes. Aucun nouvel endpoint.

Le diagnostic :

1. Compare la valeur `CameraInfoBean.id` de la RTC
   classique au `devId` Tuya **déjà sélectionné**.
   Affiche uniquement :
   `identifiant_tuya_egal`,
   `identifiant_tuya_different` ou
   `identifiant_non_verifiable`.
   Une égalité confirme au mieux une cohérence **interne
   Tuya**, pas l'identité avec la C9C AOSU.
2. Appelle **en RAM**, sans réseau, la vraie fonction
   `inspect_rtc_media` utilisée par le moteur Python,
   sur chacune des deux réponses RTC.
3. Affiche si le constructeur Python a pu préparer
   un SDP AES/KCP complet pour IPC-v4 et pour le SDK classique.
   Le SDP et les identifiants restent exclusivement
   en mémoire temporaire et ne sont ni publiés ni stockés.
4. Distingue la préparation des champs de la parité
   native **non prouvée**.
5. Bloque sur la C9C autonome tout envoi actif vidéo
   ou réveil quand la cible Tuya n'est qu'un
   appareil unique de l'inventaire, sans identité forte.
   Les informations de session privées antérieures
   sont invalidées dans ce cas.

Aucune offre n'est envoyée, aucun relais ouvert,
aucune connexion P2P effectuée, aucune commande PTZ.

## Prochain test

Installer `0.8.13-beta40`, redémarrer Home Assistant,
forcer `Ctrl+F5`, puis cliquer **une seule fois**
sur « Préparation SDK » de la C9C autonome.

Partager le texte anonymisé des nouvelles lignes :
- `SDK RTC id = devId Tuya` ;
- `Préparation SDP Python : IPC-v4` ;
- `Préparation SDP Python : SDK classique` ;
- `Champs Thing-4 cohérents avec le constructeur Python`.

Interprétation :
- Si les deux SDP sont préparables : la cause probable
  du manque de vidéo **ne se réduit pas** à des champs
  RTC manquants ; la parité du protocole natif, la
  signalisation et la correspondance caméra deviennent
  les priorités.
- Si seule la RTC classique permet la préparation :
  cela indique une différence exploitable du format
  de configuration ; ne pas automatiquement substituer
  l'endpoint dans le flux vidéo sans validation de la
  cible et de la session.
- Si l'ID RTC ne correspond pas au `devId` sélectionné :
  ne pas envoyer d'offre à ce destinataire.

## Validation

Les tests hors ligne utilisent **la vraie fonction Python**
`inspect_rtc_media` avec des valeurs totalement synthétiques
pour fabriquer un SDP en RAM. Ils vérifient les réponses
complètes, malformées, les types non-4, la concordance
d'identifiants et l'absence de secrets dans le rapport.

Les trois caméras historiquement fonctionnelles, leurs PTZ
et toutes les entités HA sont inchangées.

**Aucun code, APK ou binaire propriétaire n'est publié.**
