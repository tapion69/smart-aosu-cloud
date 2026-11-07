# Smart AOSU Cloud 0.8.13-beta6 — audit passif de routage C9C

Sur le compte de test externe, l'identité AOSU/Tuya n'est pas confirmée : zéro concordance des numéros de série, coopUUID AOSU absent, catégorie et modèle Tuya absents. Une offre SDP a été envoyée puis acquittée par MQTT, sans réponse vidéo.

- Le bouton **Vérifier identité** affiche des indicateurs anonymisés de la branche PTZ AOSU (Gz/Ty), du fournisseur P2P déclaré et du type P2P, déjà disponibles en mémoire.
- Vérifie si le SN AOSU correspond exactement à l'identifiant de l'appareil Tuya, sans jamais retourner les valeurs.
- Précise que les champs d'inventaire AOSU ne prouvent pas le protocole vidéo réellement utilisé.
- Ne modifie **ni** la sélection de caméra **ni** les requêtes de connexion, offres vidéo, décodeur, contrôleurs H1L/C5L ou PTZ.
- Aucune requête réseau supplémentaire, donnée personnelle, APK, capture ou journal ajoutés.

**Test chez l'utilisateur :** mettre à jour, recharger Home Assistant et cliquer uniquement sur **Vérifier identité**. Ne pas relancer la vidéo sans avoir étudié le résultat.
