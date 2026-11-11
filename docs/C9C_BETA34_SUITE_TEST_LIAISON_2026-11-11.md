# Smart AOSU 0.8.13-beta34 — suite du test CP inverse C9C

Date : 11 novembre 2026. Ce test est destiné uniquement à l'installation
**C9C autonome sans H1L**, pas aux caméras de la station H1L.

## Fait établi par les captures de la beta33

La fiche Tuya beta30 obtenue annonce un type de P2P SDK Thing (code 4), mais
aucun SN, catégorie vidéo ni référence AOSU permettant une correspondance.
La fiche AOSU a un SN concordant, sans référence Tuya, mais le diagnostic
beta33 a retourné `device_id_aosu_non_confirme` **avant** d'envoyer
l'appel inverse `getListByCoopUUIDList`.

Le premier résultat n'est donc ni une réponse vide du serveur AOSU,
ni la preuve que la caméra est incompatible.

## Changement beta34

- Le `deviceId` de la C9C est lu depuis le champ explicite de la
  fiche `getInfoBySn` ou du **même enregistrement SN** de `getList`,
  lorsque l'un de ces champs existe. Il reste en mémoire privée uniquement.
- Le SN de `getInfoBySn` doit être confirmé et ne pas être contradictoire.
- Même sans aucun `deviceId` AOSU disponible, un clic explicite sur
  **Fiche AOSU** peut effectuer une seule recherche inverse en lecture
  seule avec un identifiant authentifié de l'inventaire Tuya récent.
- Si une correspondance `coopUUID` est renvoyée mais qu'aucun
  `deviceId` AOSU lié au SN n'existe, l'état est
  `reference_cp_resolue_identite_non_confirmee`, **jamais** une
  identité exacte.
- Seul le retour correspondant exactement à la référence CP fournie
  **et** au `deviceId` AOSU lié au SN autorise le résultat
  `liaison_exacte_confirmee`. Ce diagnostic ne déclenche
  néanmoins **aucune** publication MQTT ni aucune vidéo.
- Le message de la carte distingue désormais **référence CP résolue**
  et **liaison prouvée**, sans afficher les valeurs privées.

Les composants média existants ne sont pas modifiés. Le délai d'une
heure de la lecture de fiche AOSU est conservé, sans retry automatique.

## Test physique utilisateur

1. Installer la version 0.8.13-beta34 puis redémarrer Home Assistant
   pour charger le code Python.
2. Sur l'installation C9C autonome, actualiser la carte navigateur
   (Ctrl+F5). Éviter les boutons vidéo et réveil.
3. Cliquer `Fiche Tuya` pour remplir le cache. Son inventaire doit
   être récent (moins de 10 minutes).
4. Cliquer `Fiche AOSU` **une fois**. Si le test précédent date de
   moins d'une heure, attendre la fin de ce délai avant de recommencer.
5. Transmettre uniquement le texte anonymisé de la carte.

## Lecture de résultats attendus

- `reference_non_resolue` : la valeur Tuya n'est pas résolue par
  l'API AOSU (ou cette API ne fonctionne pas pour ce type d'ID).
- `reference_cp_resolue_identite_non_confirmee` : le serveur reconnaît
  la référence, mais aucun ID de caméra issu d'AOSU ne permet de
  prouver le destinataire.
- `liaison_exacte_confirmee` : comparaison doublement exacte,
  future analyse ciblée de la session SDP possible, pas de vidéo lancée.
- `schema_non_reconnu` : la structure réelle du serveur diverge
  de la structure documentée dans les classes DEX.
- `inventaire_tuya_absent` ou `inventaire_tuya_expire` :
  lire l'inventaire Tuya avant le test AOSU.
- `numero_serie_aosu_non_confirme` : la réponse AOSU ne fournit
  pas de SN fiable et la recherche inverse est bloquée.
- `identifiants_aosu_contradictoires` : deux réponses AOSU incompatibles ;
  bloquer la recherche plutôt que de faire un mauvais rapprochement.

Aucun APK OEM, identifiant, numéro de série, compte, mot de passe,
clé Tuya ou média de l'utilisateur n'est intégré à GitHub. Les
tests CI portent exclusivement sur des réponses synthétiques.
