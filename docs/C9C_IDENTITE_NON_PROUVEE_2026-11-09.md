# Smart AOSU Cloud — C9C autonome : diagnostic d'identité après beta26

**9 novembre 2026 — contrôle manuel « Vérifier identité ».**

## Résultat observé (sans identifiants privés)

- État : `identite_non_prouvee` ; liaison exacte : non.
- SN AOSU : disponible dans le cache privé, mais **0** concordance avec les champs SN de l'inventaire Tuya.
- CoopUUID AOSU : absent ; correspondances coopUUID : **0**.
- Caméra Tuya sélectionnée par heuristique `appareil_tuya_unique_sans_categorie_video`.
- Catégorie Tuya : absente ; modèle Tuya : absent.
- SN AOSU identique à l'ID Tuya : **0**.
- Branche PTZ AOSU : `Ty` (indice de contrôle, **pas** identité du flux vidéo).
- Fournisseur P2P déclaré : `INDETERMINE` ; type P2P : absent.
- Référence Tuya visible dans l'inventaire AOSU : absente.

## Interprétation

Ce contrôle confirme que **l'identité de l'appareil Tuya ciblé n'est pas vérifiée**.
Il ne démontre pas que la cible est mauvaise, car les références nécessaires
pourraient être absentes de la réponse de liste AOSU/Tuya.

Les observations beta26 (réveil DP149 vrai, PUBACK offre, aucune SDP)
n'établissent pas que l'offre atteint la véritable C9C autonome.

## Prochaine étape sans beta ni commandes vidéo

Le bouton **Fiche AOSU** existe déjà sur la carte C9C autonome et appelle
l'API de lecture `/v1/dev/getInfoBySn` via
`probe_c9c_detail` avec temporisation d'**une fois par heure**.

Il examine exclusivement en mémoire les champs de référence connus
(`cpDeviceId`, `coopUUID`, `cpUuid`, `deviceUuid`, etc.), puis compare
aux identifiants Tuya présents. Le résultat est expurgé : aucune valeur de
SN, de référence, de jeton ou d'URL n'est affichée.

**Demander un seul essai « Fiche AOSU »** et relever :
- Fiche obtenue/refusée et références présentes ;
- `correspondance_reference_tuya` ;
- SN concordant ou contradictoire ;
- fournisseur et type P2P déclarés.

Si la fiche ne permet toujours pas de relier l'identité, investiguer les
sources d'identifiants dans les réponses AOSU et l'inventaire Tuya, avant
d'essayer une nouvelle offre MQTT. Aucune déduction par nom de caméra ni
substitution arbitraire d'UID/serial.

**Version installable inchangée : `0.8.13-beta26`**. Les trois caméras
déjà fonctionnelles (C5L + 2× C9C/H1L) ne sont pas modifiées.
