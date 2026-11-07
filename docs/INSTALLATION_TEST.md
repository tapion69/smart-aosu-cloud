# Installation de test — Smart AOSU Cloud 0.8.12-beta2

**Bêta expérimentale, pas une release HACS stable.** Test prévu sur un second Home Assistant, sans remplacer l'installation 0.8.10 fonctionnelle du développeur.

## Préparer le testeur

Il doit disposer de ses deux fichiers AOSU 5.10.12 obtenus de manière autorisée sur son ordinateur :

- `Aosu_5.10.12_21839.apks.apk` — APK Lite compatible, environ 1,69 Mo.
- `Aosu_5.10.12_OEM_resources.zip` — complément OEM compatible, environ 87 Ko.

**Ne pas importer l'APK AOSU complète de ~200 Mo :** seule la version Lite de référence est supportée par cette bêta. Ne jamais publier ni placer ces fichiers dans le dépôt GitHub.

## Installer l'intégration

Installer cette version du code source dans Home Assistant via le catalogue communautaire quand elle y sera disponible. Pour un essai avant publication, l'archive d'intégration peut être copiée par le mainteneur ; cela ne modifie pas le parcours de configuration de l'utilisateur. Redémarrer Home Assistant après l'installation.

## Configurer entièrement via l'interface

1. Ouvrir **Paramètres → Appareils et services → Ajouter une intégration**.
2. Rechercher **Smart AOSU Cloud**.
3. À l'écran **Importer les ressources AOSU**, cliquer sur chacun des deux champs *Choisir un fichier* et sélectionner les fichiers depuis l'ordinateur ou le téléphone de l'utilisateur.
4. Cliquer sur **Valider**. L'intégration vérifie la structure, les empreintes, les vecteurs de chiffrement et enregistre les deux fichiers dans `/config/smart_aosu_cloud/` avec leurs noms attendus. Elle ne les transmet à aucun serveur externe.
5. À l'écran **Connexion AOSU**, entrer ses identifiants et éventuellement l'adresse IPv4 privée de la station H1L. Aucune configuration manuelle de `profile.json` n'est nécessaire.
6. Contrôler les entités créées. Ajouter les cartes vidéo/PTZ en suivant `CARTES_LOVELACE.md`.
7. Tester la vidéo avant le PTZ ; tester une seule caméra à la fois et vérifier l'arrêt du mouvement au relâchement.

Le formulaire reconnaît les ressources déjà présentes dans le dossier : il ne redemande pas l'APK à chaque redémarrage ou mise à jour. Si les fichiers ont été corrompus, il les redemandera.

## Symptômes et limites

- **APK invalide / version incompatible** : seule la version AOSU 5.10.12 étudiée est acceptée. Sélectionner la vraie APK Lite et non la version complète.
- **OEM invalide** : choisir l'archive correspondant à la même version AOSU.
- **Connexion AOSU refusée** : le profil Android fictif est expérimental et doit encore être validé. Ne pas réessayer en boucle : une limitation d'une heure entre tentatives d'authentification est prévue par l'intégration.
- **Vidéo / PTZ absent** : les modèles différents de C5L / C9C3CA11-H1L ne sont pas validés. L'autorisation initiale PTZ C9 doit être confirmée explicitement.
- **Système de sécurité** : ne pas utiliser cette préversion pour protéger seul un lieu.

Pour un retour de test, indiquer les versions HA et Smart AOSU, modèles caméra/station, succès de l'importation, connexion, vidéo et PTZ, et seulement des erreurs expurgées. **Ne jamais joindre** APK, OEM, credentials, IP, MAC, PCAP, `profile.json`, captures vidéo ou logs bruts.
