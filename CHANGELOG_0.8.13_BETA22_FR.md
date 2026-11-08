# Smart AOSU Cloud 0.8.13-beta22 — correction du blocage C9C

## Cause
La bêta21 échouait avec erreur_execution_sans_details car une instruction
tentait de modifier reveil_et_video avant sa création par le moteur MQTT.
Ce KeyError arrêtait le test avant le réveil et l'offre.

## Modifications
- Suppression de l'accès prématuré à reveil_et_video.
- Lecture du résultat seulement après le retour du moteur MQTT.
- Nouveau test hors réseau exécutant réellement la branche corrigée
  avec un résultat d'offre simulé.
- Aucun changement aux protocoles RTC/MQTT, au PTZ ou aux chemins C5L/H1L.

## Test physique
Après mise à jour et redémarrage HA, recharger la carte navigateur et
attendre la fin des dix minutes de protection du réveil. Cliquer une seule
fois sur Réveil + vidéo, puis communiquer État, sans données personnelles.
