# Smart AOSU Cloud — résultat de la C9C autonome en beta31

**9 novembre 2026 — résultat de l'unique bouton Diagnostic complet sur Home Assistant.**

## Compte rendu communiqué

- Version : `0.8.13-beta31`. `diagnostic_complet_termine` (les cinq
  lectures requises ont été acceptées, et l'étape modèle a été sautée).
- Cible : `appareil_tuya_unique_sans_categorie_video` (sélection
  heuristique, identité non confirmée).
- Appels à Tuya : **5 sur 6 possibles**.
- SN : **absent de la fiche Tuya**.
- Référence AOSU/coopUUID : **indisponible pour comparaison**.
- `skills.p2pType=4` : classement SDK **Thing**, sans preuve de l'identité AOSU.
- La fiche Tuya a été acceptée ; `productId` unique **concordant**
  entre inventaire et fiche Tuya. Ceci confirme la cohérence entre deux
  sources Tuya, **pas** avec la caméra AOSU.
- `productVersion` absent ; méthode `thing.m.product.thing.model`
  non appelée : `non_tentee_version_absente`.
- `thing.m.product.info.get` accepté ; aucune catégorie, modèle,
  capacité vidéo, bloc P2P ou WebRTC **reconnu par le parseur b31**.
  Une absence de drapeau n'est pas preuve de l'absence de ces
  champs dans toute la réponse brute (parsing à structure bornée).
- `thing.m.ipc.config.get` (IPC v2) : accepté.
- `m.ipc.v4.rtc.config.get` (IPC-v4) : accepté.
- `thing.m.rtc.config.get` (RTC classique) : accepté.
- Les trois analyses RTC rapportent les mêmes indicateurs :
  `WebRTC=true`, `auth=true`, `moto_id=true`, `msid=false`,
  `msid_ambigu=false`, `ICE=true`, `session=true`,
  `AES/KCP=true`, `TURN=true`.
- Aucun réveil, aucune offre MQTT, aucune vidéo ni PTZ déclenchés
  par ce diagnostic.

## Interprétation technique

Le bilan clôt efficacement les vérifications d'**existence** des champs
sur les API déjà connues. Nous n'avons pas de correspondance forte
SN/coopUUID entre AOSU et la cible Tuya ; les succès d'API montrent
l'accessibilité d'un appareil Tuya, sans en prouver l'identité vidéo.

Des indicateurs RTC semblables dans trois réponses ne signifient pas
que les trois API utilisent la même session ou que la caméra accepte
effectivement la signalisation envoyée par l'intégration.
L'absence de `msid` visible ne prouve pas l'incompatibilité WebRTC :
il pourrait être construit à une étape ultérieure. Le PUBACK reçu
dans la beta26 était un accusé du broker, et aucune réponse SDP n'a
été observée.

## Prochain chantier : hors réseau et sans répétition utilisateur

1. **Ne plus publier un nouveau diagnostic pour chaque drapeau.**
   Le rapport beta31 rassemble les résultats du protocole et du
   produit connus dans une action unique.
2. Examiner en priorité, hors ligne, le chemin réel de la C9C
   dans l'APK AOSU 5.10.12 : choix `getSdkProvider`,
   `IPCThingP2PCamera.createDevice`, routage de la signalisation,
   création de l'identifiant session et association AOSU/Tuya.
3. Comparer cette chaîne aux chemins Python existants uniquement
   avec des traces synthétiques. Si un défaut de routage ou
   d'enveloppe est démontré, le corriger sur la C9C autonome
   dans un changement isolé, avec tests de non-régression.
4. **Ne pas transformer automatiquement** `p2pType=Thing`,
   `productId` concordant côté Tuya ou `WebRTC=true`
   en identité AOSU/Tuya prouvée.
5. Maintenir les moteurs C5L, les deux C9C derrière H1L,
   les commandes PTZ et toutes les entités existantes inchangés.

Aucun identifiant, mot de passe, clé, productId, SN, URL ou SDP
n'est conservé dans ce document.
