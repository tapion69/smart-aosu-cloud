# C9C — récupérer une référence CP déjà présente dans la fiche détaillée AOSU

**14 novembre 2026 — branche expérimentale / PR n° 4, aucune action caméra.**

## Défaut identifié dans le code réel

La fonction `probe_c9c_detail` effectue déjà la lecture autorisée
`/v1/dev/getInfoBySn` pour la **seule C9C autonome** et inspecte sa
réponse en mémoire. Mais `remember_ty_cp_uuid_from_aosu_detail`
mémorisait exclusivement `cpDeviceInfo.cpUuid`.

Il existe dans le SDK AOSU 5.10.12 une **autre voie typée**
`UUIDInfoWebDataItem.coopUUID → GzDeviceInfo.cpDeviceId →
ThingIPCSdk.createCameraP2P(devId)`. Notre lecteur détaillé
n'alimentait pas ce deuxième identifiant même si `coopUUID`,
`cpDeviceId` ou `cpDeviceInfo.cpDeviceId` étaient présents dans
la réponse déjà téléchargée.

**Ne pas confondre les namespaces :**
`cpDeviceInfo.cpUuid` est une référence UUID côté plate-forme Ty ;
`coopUUID/cpDeviceId` est la référence CP qui peut être le
`devId` Tuya. Un simple `deviceId` AOSU, un modèle
`C9C`, une seule caméra ou un UUID Tuya non lié ne suffisent pas.

## Correctifs

Nouveau module `c9c_cp_detail_identity.py` :

1. Parcourt **uniquement** les conteneurs attendus de la réponse
   AOSU déjà en RAM, avec profondeur et nombre de nœuds limités.
2. Requiert `errno=0`, un `sn` **exact** correspondant à la
   C9C actuelle et **aucun** SN d'autre caméra.
3. Vérifie les trois références CP à l'aide de
   `extract_c9c_cp_reference` existant, refuse formats invalides,
   valeurs contradictoires sur une même fiche ou entre plusieurs fiches.
4. Conserve `cp` seulement en **RAM**, lié au SN, SID et UID AOSU,
   avec expiration au bout de 3 600 secondes.
5. Compare également cette valeur à celle de `getList` si elle
   existe. **Toute contradiction ferme la sélection** au lieu de choisir
   arbitrairement une source.
6. Efface le cache à chaque nouvelle authentification, absence
   de topologie C9C, erreur de rafraîchissement ou fermeture.

Points de raccordement :
- `c9c_detail_probe.py` : extrait CP et Ty cpUuid **avec la même
  réponse HTTPS existante** ; aucun appel de plus.
- `tuya_rtc_inventory.py` : le sélecteur typé du direct
  utilise `resolve_aosu_cp_device_id`.
- `c9c_cached_video_preflight.py` et `tuya_live_preview.py` :
  la garde locale de Play sait prendre en compte la nouvelle référence
  sans déclencher de nouvelle tentative MQTT.
- `c9c_identity_diagnostic.py` et `__init__.py` :
  le diagnostic existant révèle uniquement une **étiquette de
  provenance** (`getlist_sn`, `detail_sn_session`,
  `sources_aosu_contradictoires`, `aucune`), jamais un SN,
  `devId`, token ou contenu de réponse.

## Tests et portée

`tests/test_c9c_cp_detail_identity.py` : **17 vérifications hors
ligne** pour les trois emplacements CP reconnus, le SN exact,
les duplications, les contradictions, les mauvaises sessions,
la durée de vie, les réponses refusées, la garde de Play,
le raccordement au diagnostic et l'absence de requête HTTP supplémentaire.

Le workflow exécute également les tests historiques du détail AOSU
et de la passerelle Tuya :

https://github.com/tapion69/smart-aosu-cloud/actions/runs/43624970772

## Ce qui est prouvé / non prouvé

**Prouvé dans le code :** si `getInfoBySn` fournit effectivement
une référence CP non contradictoire pour le SN C9C, elle ne sera
plus ignorée, et pourra être comparée de façon typée à
`Tuya.devId` dans le moteur expérimental.

**Non prouvé chez le frère :** que son serveur retourne ce champ.
Le résultat de bêta43 `cp_uuid_absent_du_detail` concernait
le **Ty cpUuid** et ne permettait pas à lui seul de conclure à
l'absence de tout `cpDeviceId/coopUUID`. Si les trois champs
CP sont également absents, cette correction **ne fabrique pas**
de correspondance et le direct reste interdit.

Le nouveau moteur P2P Python est déjà préparé dans la PR, mais
**n'est pas branché au bouton Play**. Aucune nouvelle version
installable, aucun test chez le frère, aucun changement du
traitement vidéo/PTZ historique C5L/H1L.

**`main` : `0.8.13-beta44-rc3`, inchangé.**
