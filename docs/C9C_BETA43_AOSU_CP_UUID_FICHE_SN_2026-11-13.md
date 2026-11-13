# Smart AOSU — bêta43 : source réelle du cpUuid Tuya de la C9C

Date : 13 novembre 2026. Branche autonome C9C sans H1L.

## Retour réel de la bêta42

La carte confirme **deux versions b42** (navigateur et serveur).
La « Fiche Tuya » obtient l'unique appareil et un `uuid` Tuya ;
le P2P SDK Thing est type 4. Aucun numéro de série AOSU n'est renvoyé
dans cette fiche. « Vérifier identité » affiche :
- `cpUuid Ty AOSU présent : non` ;
- `UUID Tuya récent : oui` ;
- `cpUuid AOSU = UUID Tuya : non` ;
- `sélection RTC : appareil_tuya_unique_sans_categorie_video` ;
- aucun identifiant AOSU/Tuya exact démontré.

Il ne faut **pas** conclure que `cpUuid` n'existe pas dans l'APK
ou dans le SDK Android. La bêta42 ne lit la valeur AOSU que
depuis l'enregistrement HTTP `/v1/dev/getList`.

## Ce que le DEX 5.10.12 établit

L'audit statique de `classes11.dex` / `classes15.dex`
(`tools/aosu_cp_cache_route_offline.py`) établit notamment :

- `UUIDInfoWebDataItem.coopUUID` est converti en
  `GzDeviceInfo.cpDeviceId` ;
- `DeviceInfoRepoImpl.loadDeviceInfoList` charge les
  appareils depuis AOSU et consulte **aussi**
  `TyDeviceInfoSource` du SDK de plateforme ;
- la jointure lit `cpDeviceId` et la source Tuya,
  avec un cache local ;
- les événements plateforme peuvent enrichir le
  `GzDeviceInfo` avec `setCpDataInfo`.
- La branche `Iot.Ty` de `DeviceInfoExtKt` lit
  `GzDeviceInfo.cpDeviceInfo.cpUuid`.

**Conclusion :** la fiche interne `GzDeviceInfo` de
l'application Android n'est pas nécessairement identique
au JSON brut AOSU `getList`. L'absence de `cpDeviceInfo`
dans `getList` est compatible avec un enrichissement
local **après réception** des réponses cloud. Ces références
DEX ne prouvent pas que la valeur sera renvoyée par
`getInfoBySn`.

## Correction ciblée bêta43

Un **unique autre point d'entrée déjà existant** est utilisé :
le bouton manuel `Fiche AOSU` appelle
`/v1/dev/getInfoBySn` comme auparavant.

La bêta43 vérifie exclusivement si la réponse contient
`cpDeviceInfo.cpUuid` **dans le même enregistrement
dont `sn` correspond exactement à la C9C autonome**.
Aucune valeur dérivée ou devinée depuis `coopUUID`,
`cpDeviceId`, `devId` ou le nom n'est acceptée.

Si un `cpUuid` explicite existe :
- il reste uniquement en RAM, avec le numéro de série,
  la session AOSU et un délai de validité d'une heure ;
- il est invalidé au changement de session, de caméra
  ou au dépassement du délai ;
- le bouton `Vérifier identité` peut ensuite comparer
  cet identifiant au `uuid` **réel** du même appareil
  Tuya, issu d'une fiche Tuya récente et de la même
  session Tuya authentifiée.

Si le champ est absent, contradictoire ou si le SN
n'est pas confirmé, il n'est ni inventé ni conservé.

Les recherches inverses AOSU `getListByCoopUUIDList`
des bêta33 à bêta36 sont **arrêtées** dans ce parcours ;
elles avaient répondu sans `deviceId`, sans preuve
d'identité. `Fiche AOSU` ne fait maintenant **qu'un**
appel réseau au lieu de deux.

## Procédure utilisateur — un seul test de cette nouvelle source

1. Installer `0.8.13-beta43`, redémarrer Home Assistant.
2. Remplacer la ressource Lovelace de la C9C autonome
   par `/smart-aosu/c9c-autonome-b43.js`
   (conserver le même type de carte et la même entité).
   `Ctrl+F5`.
3. Sur la seule C9C autonome, cliquer **Fiche AOSU**.
   Un test par heure maximum ; ne pas forcer la fréquence.
   Noter `cpUuid Ty source détail`.
4. Cliquer **Fiche Tuya**, puis **Vérifier identité**
   dans les dix minutes. Le rapport doit commencer
   par `Carte b43 ; diagnostic serveur : b43` et
   afficher `source CP AOSU` :
   `getlist_sn`, `detail_sn_session` ou `aucune`.
5. Partager **uniquement les messages anonymisés**.
   Aucun compte, identifiant, SN, IP, clé ou jeton.

Résultats :
- `cp_uuid_detail_sn_verifie` :
  référence AOSU effectivement obtenue avec un SN exact,
  on peut faire une comparaison de même namespace.
- `cp_uuid_absent_du_detail` :
  **la seconde API HTTP ne fournit pas ce champ**.
  Ne pas répéter le test ; la suite doit traiter
  l'enrichissement `TyDeviceInfoSource` / SDK et
  non accumuler des variantes de lecture cloud.
- Un rapprochement Ty UUID exact est une preuve
  **d'association d'identifiants**, pas une preuve
  que la session vidéo Thing-4 ou le SDP fonctionnent.

## Protection des caméras existantes

La C5L et les deux C9C3CA11 derrière H1L utilisent
leurs contrôleurs vidéo et PTZ inchangés. Les lectures
n'émettent **aucune** offre MQTT, commande vidéo ou PTZ.
Les commandes actives C9C autonome restent refusées
en absence de correspondance d'identité typée.

Les tests CI utilisent des réponses entièrement
synthétiques et vérifient les changements de session,
SN, identifiant contradictoire, TTL et secrets absents
des rapports. Aucun APK fournisseur ni donnée privée
n'est commis dans ce dépôt public.
