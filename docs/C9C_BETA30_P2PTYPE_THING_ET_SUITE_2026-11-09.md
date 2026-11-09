# Smart AOSU Cloud — beta30 : classification P2P Thing, identité non confirmée

**9 novembre 2026 — capture « Fiche Tuya beta30 » de l'installation externe.**

## Résultat obtenu

- Fiche Tuya : **obtenue** sur le candidat sélectionné.
- Numéro de série : absent de la fiche Tuya ; référence AOSU : indisponible.
- Modèle et catégorie Tuya : absents.
- `productId` : présent ; `productBean` : absent.
- Bloc `skills` : présent.
- `skills.p2pType` : **Thing (code SDK 4)**, conformément à l'énumération `ThingCameraConstants.P2PType` analysée dans l'APK AOSU 5.10.12.
- `p2pSpecifiedType` : absent.
- Bloc de capacités : absent ; bloc `p2pConfig` : absent ; indicateur P2P booléen : absent.
- ID de la réponse Tuya = ID de la requête : oui.
- Correspondance fiable entre ce compte Tuya et la caméra AOSU : **NON**.
- Le diagnostic n'a envoyé aucune offre MQTT, commande, vidéo ou PTZ.

## Interprétation

La **valeur Thing = 4 est déclarée par le candidat Tuya**. Elle ne confirme
ni que ce candidat est la C9C de l'utilisateur, ni qu'AOSU utilise
effectivement Thing P2P pour sa vidéo. Le SN reste absent, la référence
coopUUID indisponible, et la sélection actuelle reste heuristique
(`appareil_tuya_unique_sans_categorie_video`).

Le PUBACK de la beta26 ne prouvait que la réception de la publication
par le broker MQTT. Aucun SDP ni JPEG n'a été obtenu. Ne pas relancer
des offres vidéo sur la seule base de p2pType=4.

## Prochaine vérification proposée

Le code `tuya_uid_gateway.py` autorise déjà l'action de **lecture seule**
`thing.m.product.info.get` version **1.0**, avec un paramètre
`productId` validé (sans autre champ). Il devient possible de préparer
une sonde dédiée, manuelle, qui récupère le `productId` du candidat Tuya
**en mémoire** et demande les métadonnées du produit. Le diagnostic
public doit limiter la sortie à des valeurs prédéfinies : présence de
catégorie caméra, classe de produit, famille de modèle et éventuelles
capacités IPC, sans divulguer `productId`, contenu brut, tokens ou
identifiants.

- **Prérequis** : session Tuya authentifiée et un seul candidat AOSU C9C autonome.
- **Limites** : même protections de fréquence et aucun appel supplémentaire
  par défaut ; déclenchement manuel et une seule lecture si le produit
  est disponible.
- **Fail-closed** : un productId ou une catégorie caméra ne prouve pas
  la liaison AOSU/Tuya. L'objectif initial est seulement de distinguer
  « produit susceptible d'être une caméra » de « métadonnées insuffisantes ».
- **Non-régression** : ne pas modifier les moteurs C5L/H1L, le PTZ,
  le réveil, le SDP, l'authentification ni le routage vidéo.

Version installable actuelle : **0.8.13-beta30**.
