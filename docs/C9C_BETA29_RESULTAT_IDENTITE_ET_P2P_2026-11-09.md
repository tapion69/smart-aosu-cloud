# Smart AOSU Cloud — C9C autonome : résultat Fiche Tuya beta29

**9 novembre 2026 — résultat manuel communiqué par l'utilisateur.**

## Observations

- Fiche Tuya : **obtenue**.
- Numéro de série : **absent de la fiche Tuya** (et non pas différent).
- Référence AOSU : **indisponible** ; aucune comparaison coopUUID fiable.
- Modèle : **absent** ; catégorie : **absente**.
- Champ `productId` : **présent**, mais **pas** de bloc `productBean` et pas de productId dans ce bloc.
- Bloc `skills` : **présent** ; champ `p2pType` : **présent**. Sa **valeur** et sa sémantique ne sont pas établies dans ce diagnostic.
- Bloc `capabilities` : absent ; bloc `p2pConfig` : absent ;
  indicateur booléen de support P2P : absent.
- L'identifiant Tuya dans la réponse est identique à l'identifiant demandé.
- **Identité AOSU/Tuya non démontrée.** Aucun réveil, offre MQTT, SDP, vidéo ou PTZ n'a été envoyé par ce contrôle.

## Conclusions

Le seul appareil Tuya sélectionné par `appareil_tuya_unique_sans_categorie_video`
est accessible et expose un `productId` et un champ `p2pType`, sans SN,
modèle ou catégorie exploitables pour le relier à la C9C connue côté AOSU.
La présence d'un `p2pType` est un indice de configuration, **pas** une
preuve que cet appareil est la C9C ou qu'il prend en charge le transport vidéo
utilisé par l'application AOSU.

La beta26 a confirmé : réveil DP149=true, offre MQTT acquittée par le broker,
compteurs SandO activés, mais aucune réponse SDP. Ne pas répéter le démarrage
vidéo sans nouveau fait probant.

## Étape suivante proposée

Inspecter **hors ligne** les définitions du champ `skills.p2pType`
et ses consommateurs dans les 17 DEX de l'APK AOSU complet (déjà analysé),
afin de savoir si le champ possède une interprétation documentable. Si cette
interprétation est confirmée, créer un diagnostic anonyme de
**classification de p2pType** sur `thing.m.device.get` sans exposer les
identifiants. Les contrôles côté AOSU restent séparés tant qu'aucun lien
fort SN/coopUUID ou référence de jumelage n'est découvert.

**Version installable actuelle : 0.8.13-beta29.** Aucune modification
du moteur vidéo C5L / H1L ni des commandes PTZ.
