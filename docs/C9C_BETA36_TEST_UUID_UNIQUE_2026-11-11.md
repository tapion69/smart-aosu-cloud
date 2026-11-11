# Smart AOSU 0.8.13-beta36 — C9C autonome : un seul UUID, schéma AOSU anonymisé

Date : 11 novembre 2026. Aucun changement de la lecture vidéo, des
commandes PTZ ou des équipements C5L et C9C3CA11/H1L.

## Résultat réel de la beta35

- Fiche Tuya : type P2P SDK Thing 4, UUID présent, mais aucun numéro
  de série ni lien AOSU/Tuya démontré.
- Fiche AOSU : SN concordant, `deviceId` AOSU non confirmé.
- L'appel `getListByCoopUUIDList` avec **deux** références a retourné
  `champs_identite_manquants`. Ce statut signifie que la réponse
  contient au moins une entrée, mais qu'au moins une entrée n'a pas
  les deux champs `coopUUID` et `deviceId` attendus. Il **ne
  prouve pas** que la référence envoyée a été reconnue.

## Audit de l'APK complète AOSU 5.10.12

Inspection hors ligne de l'APK fournie, sans connexion ni publication
des classes propriétaires :

- Dans `classes15.dex`, la méthode
  `DeviceWebService$getDeviceInfoByCorpUuid$1.OooO00o`
  appelle `UUIDInfoWebData.OooO00o` (récupération de la liste), puis
  `kotlin.collections.CollectionsKt.firstOrNull`.
- L'élément `UUIDInfoWebDataItem` dans cette même DEX contient
  `coopUUID`, `deviceId`, `devModel`, `devType`,
  `svcType`, `bindInfo` et `online`.

Ce parcours indique que le client Android travaille ensuite
sur **un élément** de réponse. Il ne prouve pas que le serveur
rejette les tableaux, ni qu'une réponse dépourvue d'identifiants
identifie la bonne caméra.

## Modification beta36

1. Garder la liste privée des vraies références disponibles issue
   de l'inventaire et de la fiche Tuya de la C9C autonome.
2. Choisir **un seul** identifiant. Priorité aux références
   explicitement désignées CP (`cpDeviceId`, `coopUUID`,
   `cpUuid`), puis `uuid`, `devUuid`, `deviceUuid`,
   et seulement en dernier recours `devId`.
3. Une seule lecture HTTPS à `getListByCoopUUIDList`, avec un
   unique champ `coopUUID[]`. Pas de relance automatique.
4. Afficher le type de l'identifiant testé, le nombre d'entrées
   et des booléens sur les **noms de champs connus de l'APK** :
   `coopUUID`, `deviceId`, `devModel`, `devType`.
   Aucun identifiant, nom d'appareil, token, clé ou valeur reçue
   du serveur n'est affiché, journalisé ou conservé.
5. Les états `reponse_sans_coop_uuid` et
   `coop_uuid_retourne_sans_device_id` distinguent les réponses
   incomplètes. Une identité AOSU/Tuya ne peut être prouvée
   qu'avec le même identifiant CP **et** un identifiant AOSU
   déjà lié au numéro de série de la C9C.
6. Conserver le verrou d'une heure pour le bouton **Fiche AOSU**
   et les protections des accès Tuya. Aucun bouton vidéo ou
   réveil n'est déclenché par ce diagnostic.

## Nouveau test

1. Installer `0.8.13-beta36`, redémarrer Home Assistant, puis
   forcer l'actualisation du navigateur (`Ctrl+F5`).
2. Sur la C9C autonome : **Fiche Tuya**, puis **Fiche AOSU**
   dans les dix minutes. Attendre au moins une heure depuis
   la dernière lecture Fiche AOSU si nécessaire.
3. Partager le message anonymisé, en particulier
   `référence testée`, `liaison inverse`, `entrées AOSU`,
   `coopUUID présent`, `deviceId présent`,
   `référence CP résolue` et `liaison prouvée`.

### Interprétation

- `reponse_sans_coop_uuid` : le serveur fournit une ou plusieurs
  entrées sans champ CP exploitable ; ce n'est pas une validation.
- `coop_uuid_retourne_sans_device_id` : le serveur renvoie la
  référence demandée mais pas l'identifiant d'appareil AOSU.
  Correspondance non démontrée.
- `reference_cp_resolue_identite_non_confirmee` : référence et
  `deviceId` sont présents et conformes, mais aucun `deviceId`
  AOSU lié au SN n'est disponible pour prouver la caméra.
- `reponse_plusieurs_entrees_non_concluante` : structure non attendue
  par le parcours `firstOrNull` ; ne pas inférer d'identité.
- `liaison_exacte_confirmee` : référence exacte **et**
  `deviceId` AOSU lié au SN. Toujours aucune vidéo lancée.

Tests synthétiques : `tests/test_c9c_cp_single_b36.py`.
La validation réelle dépend du prochain retour utilisateur.
