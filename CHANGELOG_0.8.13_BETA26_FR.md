# Smart AOSU Cloud 0.8.13-beta26 — corrélation MQTT C9C autonome

## Cause suspectée et preuves

L'APK original AOSU 5.10.12 (17 DEX) révèle une chaîne précise :
SandRMap/SandO -> MqttControlBuilder -> publishDevice ->
codec PV2.2. La version 2.2 du SDK chiffre un PublishBean2_2
(data/protocol/t) en AES brut, calcule CRC32(S+O+AES) et transmet
'2.2'+CRC32+S+O+AES. Le moteur Python utilisait déjà ce format.

L'écart avéré concerne la numérotation initiale :
SandO.S=2 puis SAdd avant publish (premier S=3), et
O=floor(Math.random()*1_000_000)+1000 sur quatre octets.
La beta25 utilisait S=1,2 puis quatre octets aléatoires arbitraires.

## Changement limité

- Uniquement le mode vidéo manuel C9C autonome : première publication
  sigQry S=3, seconde offre S=4, candidat éventuel S=5,
  disconnect S=5 ou S=6.
- O entier indépendant dans [1000, 1000999], même valeur pour
  toute la session MQTT, sans exporter cette valeur.
- Aucune modification des méthodes de chiffrement, JSON, CRC,
  réveil DP149, authentification ou caméra/flux C5L/H1L.
- Diagnostic 'compteur SDK C9C beta26 : actif' et tests synthétiques
  du séquencement et de l'enveloppe. Aucune analyse DEX sensible livrée.

## Test

Mettre à jour et redémarrer Home Assistant, actualiser la carte,
fermer le direct de l'application AOSU, attendre la fin du cooldown
de réveil, puis cliquer **une seule fois sur Réveil + vidéo**.
Une fois l'essai terminé, communiquer uniquement État.
Un PUBACK n'est pas une confirmation de SDP ; l'absence de SDP
reste possible même avec les nouveaux compteurs.
