# Smart AOSU 0.8.13-beta35 — C9C autonome : contrôle CP à partir des vrais UUID Tuya

Date : 11 novembre 2026. Recherche hors ligne sur l'APK 5.10.12 et
préparation d'un test de lecture cloud, sans émission caméra ni vidéo.

## Établi par la beta34

La fiche Tuya retourne `uuid : oui`, `p2pType` du SDK Thing = 4 et
aucune référence explicite AOSU.
La fiche AOSU confirme le SN mais ne contient aucun `deviceId`
vérifiable. L'API `getListByCoopUUIDList`, interrogée avec le
`devId` de Tuya, retourne `reference_non_resolue`.

Cela ne prouve pas que la caméra C9C n'est pas compatible avec le SDK
Thing : **le champ `devId` peut différer du `coopUUID` recherché**.

## Nouveau constat dans l'APK intégrale

Dans `classes15.dex`, `TyDeviceInfoSource` utilise
`IotDevice.Oooo0OO()` (renvoie une liste de périphériques de la
plateforme SDK). L'application gère séparément
`PlatformDeviceInfo.cpDeviceId` et `PlatformDeviceInfo.cpUuid`.
Ces champs ne sont pas nécessairement accessibles dans le résultat
de `m.life.my.group.device.list` du cloud Tuya.

La fiche `thing.m.device.get` de l'utilisateur annonce cependant
qu'un champ UUID **existe**. Jusqu'à la beta34, l'intégration ne le
réutilisait pas dans le contrôle CP inverse : uniquement
`cpDeviceId` ou `devId` de l'inventaire.

## Ce qui change en beta35

- Lors du clic explicite **Fiche Tuya**, retenir temporairement les
  seules références privées et bien formées des champs
  `uuid`, `devUuid`, `deviceUuid`, `cpUuid`,
  `coopUUID`, `cpDeviceId` effectivement présents dans le
  **même appareil Tuya**. L'identité de cette fiche doit être
  concordante avec le `devId` demandé ; pas de collecte de données
  d'autres appareils, de produit ou de clés.
- Cache privé de **10 minutes** en mémoire du client, limité à quatre
  références alternatives. Aucune sauvegarde ni publication.
- Lors du clic **Fiche AOSU** après Fiche Tuya, envoyer **une seule**
  requête `getListByCoopUUIDList` avec le `devId` déjà utilisé
  et au maximum quatre identifiants alternatifs réellement obtenus.
  Le format de l'APK permet plusieurs `coopUUID[]` dans cette requête.
- Ne jamais interpréter un `UUID` renvoyé comme une preuve automatique.
  Refuser les réponses contradictoires, multiples, mal formées ou
  concernant un appareil AOSU différent.
- Le texte de la carte indique seulement **combien de références ont
  été interrogées** (1 à 5), **le type de la référence reconnue**
  (enum statique) et si la liaison est réellement démontrée.
  Aucun identifiant, SN, URL privée, token ou clé ne sort du résultat.
- Le délai **une heure entre lectures Fiche AOSU** et les restrictions
  des lectures Tuya sont conservés. Aucune modification des modules
  vidéo/PTZ, ICE, de la station H1L ou des trois caméras historiques.

## Test utilisateur

1. Mettre à jour l'intégration `0.8.13-beta35`, redémarrer HA, puis
   recharger le navigateur via `Ctrl+F5`.
2. Dans la carte C9C autonome, cliquer **Fiche Tuya** (attendre le
   résultat obtenu). Ne pas lancer la vidéo ni le réveil.
3. Dans les **10 minutes**, cliquer **Fiche AOSU**. Respecter
   l'intervalle d'une heure après la précédente consultation AOSU.
4. Transmettre la ligne anonymisée de la carte, en particulier :
   `références interrogées`, `référence retrouvée`,
   `liaison inverse`, `référence CP résolue` et
   `liaison prouvée`.

## Interprétation

- `références interrogées : 1` : pas de second UUID exploitable
  extrait de la fiche Tuya (ou cache expiré/incohérent).
- `références interrogées : 2-5` : le backend a essayé les
  références supplémentaires dans **un seul appel**.
- `reference_non_resolue` : AOSU ne résout aucune de ces références ;
  inutile de répéter le même appel.
- `reference_cp_resolue_identite_non_confirmee` : le serveur reconnaît
  une référence, mais le `deviceId` AOSU lié au SN reste absent :
  **aucune preuve de la destination vidéo**.
- `liaison_exacte_confirmee` : rapprochement doublement vérifié
  (référence CP et ID AOSU lié au SN). Cela n'ouvre aucune session
  vidéo automatiquement.
- `references_cp_multiples_ambigues`,
  `reference_cp_incoherente`, `autre_appareil_aosu` :
  protection contre des correspondances dangereuses.

Si cette piste échoue, l'enquête doit passer au mécanisme
`IotDevice` du SDK Android ou à une interface officiellement exposée,
plutôt qu'itérer encore avec des identifiants inventés.

## Validation

Tests synthétiques hors ligne dans
`tests/test_c9c_cp_uuid_batch_b35.py`.
Ils vérifient l'unicité de l'appareil, l'expiration du cache, le
lot de références, l'interdiction de conclure sans ID AOSU, la
protection contre les réponses multiples et l'absence de secrets
dans les résultats. Aucun test caméra réel n'a été effectué.
