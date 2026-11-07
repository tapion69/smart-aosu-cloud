# Cartes Smart AOSU Cloud 0.8.11-beta1

Ajouter d'abord deux ressources JavaScript (type **module**) au tableau de bord :

- `/smart-aosu/ptz-hold-b84.js`
- `/smart-aosu/c9-live-b146.js`

Remplacer les entités fictives ci-dessous par les entités créées sur **votre** Home Assistant.

## C5L

```yaml
type: custom:smart-aosu-ptz-live-b84
camera_entity: camera.ma_c5l
```

## Première C9 derrière H1L

```yaml
type: custom:smart-aosu-c9-live-b146
camera_entity: camera.ma_c9_1
camera_numero: 1
titre: "C9 n°1"
```

## Deuxième C9 derrière H1L

```yaml
type: custom:smart-aosu-c9-live-b146
camera_entity: camera.ma_c9_2
camera_numero: 2
titre: "C9 n°2"
```

Si l'adresse IP H1L a été renseignée pendant l'ajout de l'intégration, ces cartes ne nécessitent pas `ip_station`.

Pour utiliser une autre H1L dans une carte précise, ajouter `ip_station: "192.0.2.10"` en **remplaçant cette adresse de documentation** par l'adresse privée réelle de la station. Les cartes refusent les adresses publiques.

Vérifier quel numéro 1/2 pilote physiquement chaque C9 **avant** d'autoriser le PTZ. STOP doit être testé à courte durée sur une seule caméra à la fois.


## C9C Wi-Fi autonome, sans station H1L — essai vidéo

Cette configuration est différente des C9C3CA11 reliées à une station H1L.
Le PTZ de ce modèle **n'est pas autorisé** : ne pas utiliser la carte C5L
qui comporte des flèches PTZ. Ajouter la ressource JS de type module :

- `/smart-aosu/c9c-autonome-b1.js`

Puis utiliser la vraie entité créée pour la caméra autonome :

```yaml
type: custom:smart-aosu-c9c-autonome-b1
camera_entity: camera.remplacer_par_c9c_autonome_video_experimentale
```

Le bouton Essayer la vidéo lance **une seule session volontaire** avec le
moteur P2P C5L ; aucun PTZ ni démarrage automatique. Le bouton État montre
la progression et le nombre d'images JPEG réellement décodées. En cas d'échec,
cliquer sur Arrêter et relever seulement les états sans secrets.
