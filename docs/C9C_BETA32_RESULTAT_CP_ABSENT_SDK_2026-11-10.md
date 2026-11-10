# Smart AOSU — C9C autonome — résultat beta32 et enquête CP

**10 novembre 2026 — diagnostic complet fourni après vérification de mise à jour.**

## Résultat vérifié

- La version installée est confirmée par l'utilisateur comme à jour.
- Le nouveau champ **Origine référence AOSU : absente** apparaît dans le
  diagnostic : le module frontal beta32 est chargé.
- Le titre « DIAGNOSTIC COMPLET BETA31 » provient d'une chaîne statique
  non renommée dans `frontend/c9c-autonome-b1.js`. Il **ne prouve
  pas** une installation antérieure lorsque l'origine AOSU est affichée.
- `diagnostic_complet_termine` : cinq lectures Tuya, modèle produit non
  demandé faute de version produit.
- Sélection `appareil_tuya_unique_sans_categorie_video`, donc **heuristique**.
- SN : absent dans la fiche Tuya ; référence AOSU : indisponible ;
  type P2P du candidat Tuya : Thing (4) ; liaison exacte : non.
- Fiche Tuya et produit acceptés ; productId concordant entre deux
  réponses Tuya, sans preuve de correspondance avec AOSU.
- IPC v2, RTC IPC-v4 et RTC classique acceptés : indicateurs
  WebRTC/auth/moto_id/ICE/session/AES-KCP/TURN présents ;
  aucun MSID détecté, aucun MSID ambigu.
- Ce test n'a envoyé **aucune commande caméra, MQTT, SDP, vidéo ni PTZ**.

## Conclusion de la beta32

L'extracteur privé `c9c_cp_reference_b32.py` a vérifié les trois
emplacements **dans le seul enregistrement AOSU C9C autonome** :

1. `coopUUID` racine ;
2. `cpDeviceId` racine ;
3. `cpDeviceInfo.cpDeviceId`.

L'indicateur `absente` signifie qu'aucun de ces champs n'est apparu
avec une valeur non nulle dans l'enregistrement. Il ne dit rien de
tous les autres schémas ou caches de l'application Android.

L'ancienne API AOSU `/v1/dev/getInfoBySn` avait donné une fiche
avec SN concordant mais sans référence Tuya exploitable.
**Il serait inutile de répéter la même lecture pour cette raison.**

## Enquête supplémentaire hors réseau sur l'APK complet

Archive locale AOSU 5.10.12 / 17 DEX, SHA256
`ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7`.
Aucun APK, code propriétaire, compte ni secret ajouté au dépôt.

Les tables DEX confirment :

- `classes15.dex` : `DeviceBusinessImpl.getDeviceInfo` appelle
  `DeviceInfoDataRepo.getDeviceInfo` ;
- `classes15.dex` : `DeviceInfoRepoImpl` référence le composant
  `TyDeviceInfoSource`, qui contient des méthodes de chargement
  et de cache de liste d'appareils ;
- `classes15.dex` : `DeviceWebService` et ses adaptateurs
  incluent une lecture d'appareil par UUID de coopération ;
- `classes15.dex` : endpoints intégrés
  `/v1/dev/getList`, `/v1/dev/getInfoBySn`,
  `/v1/dev/getListByCoopUUIDList`, ainsi que des opérations de
  lecture par code/SSID ;
- `classes11.dex` : `UUIDInfoWebDataItem.coopUUID` et
  `GzDeviceInfo.cpDeviceId` sont présents dans le chemin d'adaptation,
  conformément au traçage antérieur du SDK.

**Limite de la preuve** : nous avons vérifié les méthodes et appels
dans le bytecode statique, mais pas observé le flux réel d'appairage
de cette C9C. Nous ne pouvons pas affirmer que `TyDeviceInfoSource`
détient effectivement son `cpDeviceId`, ni que les données absentes
de getList peuvent être reconstruites par les API authentifiées
actuellement disponibles. L'endpoint par liste coopUUID nécessite
justement la référence dont nous manquons ; ne pas le détourner avec
une valeur inventée.

## Règles pour les travaux suivants

- Conserver `0.8.13-beta32` et les trois caméras C5L + C9/H1L
  déjà fonctionnelles, ainsi que PTZ, entités et séquences vidéo.
- **Ne pas publier de beta33** uniquement pour renommer le titre BETA31
  ni pour répéter les mêmes six lectures.
- Priorité : reconstituer hors réseau les transformations
  `DeviceInfoRepoImpl` / `DeviceBusinessImpl` / `TyDeviceInfoSource`
  et établir **l'origine vérifiable** du CP ID sans exfiltrer de secret.
- Si une nouvelle source de preuve autorisée apparaît, l'intégrer
  à une seule action diagnostique consolidée et non à des boutons
  successifs, avec tests de non-régression et confidentialité.
- En l'absence d'une preuve d'identité AOSU↔Tuya, ne pas interpréter
  une réponse MQTT PUBACK, une API RTC acceptée ou le code P2P Thing
  comme confirmation de livraison d'une offre à la caméra.

Le test de la beta32 suffit pour cette étape : **aucune nouvelle
manipulation Home Assistant nécessaire**.
