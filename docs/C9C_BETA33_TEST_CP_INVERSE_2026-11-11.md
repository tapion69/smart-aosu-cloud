# C9C autonome — beta33 : vérification inverse de l'identité AOSU/Tuya

**11 novembre 2026.** Test manuel, strictement en lecture seule. Pas de vidéo, de PTZ, de réveil, d'offre MQTT ou de modification du fonctionnement de la C5L et des deux C9C3CA11 derrière H1L.

## Découverte dans l'APK AOSU 5.10.12

L'interface Retrofit de `DeviceWebService$IService` déclare
`POST /v1/dev/getListByCoopUUIDList` avec un champ
`@Field("coopUUID[]")` qui reçoit une liste. Le type de réponse
`UUIDInfoWebData` contient une liste d'éléments
`UUIDInfoWebDataItem`, avec `coopUUID` et `deviceId`.
Le mapping Android attribue `coopUUID` à `GzDeviceInfo.cpDeviceId` et
`deviceId` à `GzDeviceInfo.deviceId`.

Il est donc possible de poser la question inverse à AOSU avec un
**identifiant réel déjà reçu de Tuya**, puis de vérifier que la réponse
associe exactement cette référence au `deviceId` de la C9C récupéré
séparément dans `getInfoBySn`. **Aucune égalité n'est présumée.**
Une réponse vide ne prouve pas que la caméra est étrangère à Tuya :
le type d'identifiant peut simplement ne pas correspondre.

## Test sur l'installation C9C autonome

1. Mettre à jour et démarrer `0.8.13-beta33`, puis actualiser le navigateur.
2. Sur la carte **C9C autonome**, utiliser **Diagnostic complet** (lecture
   seule) ou **Fiche Tuya** pour charger le cache Tuya du compte. Il doit
   contenir un seul appareil valide, âgé de moins de 10 minutes.
3. Cliquer **Fiche AOSU**. La lecture originale `getInfoBySn` sera faite,
   puis au maximum **une** requête supplémentaire
   `getListByCoopUUIDList` si les préconditions sont satisfaites.
4. Transmettre **uniquement** l'état `liaison_inverse_cp.etat` et
   `liaison_inverse_cp.liaison_exacte_confirmee` (ou le texte anonymisé
   de la carte).

La recherche Fiche AOSU est limitée à un test par heure. Pas d'essai
vidéo dans ce protocole.

## Interprétation

- `liaison_exacte_confirmee` : AOSU a retourné la même référence CP
  et le même `deviceId` que la fiche AOSU correspondant au SN C9C.
  La suite sera un seul essai média distinct et expressément autorisé.
- `reference_non_resolue` : l'ID Tuya reçu n'est pas résolu par cet
  endpoint AOSU. On change de piste, sans envoyer d'offre à la caméra.
- `device_id_aosu_non_confirme` : il manque dans la fiche AOSU un
  `deviceId` lié formellement au SN de la caméra.
- `inventaire_tuya_expire` ou `inventaire_tuya_absent` : recharger
  l'inventaire et retenter seulement après le délai de limitation.
- `autre_appareil_aosu` ou `reponse_ambigue` : aucune vidéo autorisée.

L'outil ne conserve aucun identifiant privé, ne publie ni valeur CP,
ni clé locale, ni SN, ni donnée d'APK. Tous les tests de logique sont
synthétiques et hors réseau. Pas de validation physique tant que
l'utilisateur n'a pas effectué le test ci-dessus.

**Périmètre de beta33** : ajout d'un diagnostic explicite seulement,
aucune modification des fonctions vidéo/PTZ existantes.
