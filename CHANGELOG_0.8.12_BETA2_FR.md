# Smart AOSU Cloud — 0.8.12-beta2 (7 novembre 2026)

- Ajout du sélecteur de fichiers natif Home Assistant pour importer APK Lite et OEM ZIP directement depuis le navigateur.
- Vérification hors réseau de la version et du contenu, y compris empreintes et vecteurs connus ; fichiers invalides rejetés.
- Création automatique du dossier `/config/smart_aosu_cloud/` et sauvegarde sous noms attendus.
- Préservation des fichiers existants en cas d'échec de validation.
- Aucun composant propriétaire ni donnée d'installation inclus dans le dépôt.
- Les formulaires d'identifiants AOSU et d'IP facultative et la génération de profil local restent disponibles.
- Les fonctions vidéo et PTZ du candidat existant ne sont pas réécrites.
- Testé hors réseau sur des copies de référence ; test d'installation HA réel et connexion externe non encore effectués.
