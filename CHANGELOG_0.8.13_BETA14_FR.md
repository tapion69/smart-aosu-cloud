# Smart AOSU Cloud 0.8.13-beta14 — corriger le blocage local RTC IPC-v4

La beta13 avait un défaut de garde-fou : `m.ipc.v4.rtc.config.get` était utilisé par le diagnostic mais absent de `_READ_ACTIONS`. Le serveur Tuya n'avait donc pas reçu la requête.

- Ajoute l'action de lecture IPC-v4 à la liste blanche avec l'API v1.0, méthode et version documentées dans le SDK Tuya P2P indépendant.
- Conserve les paramètres stricts `devId` et HTTPS de la passerelle existante.
- Affiche l'origine catégorisée de la prochaine erreur au lieu de l'unique état `erreur_api_tuya`.
- Ne modifie ni les offres MQTT ni les contrôleurs vidéo/PTZ C5L/H1L ou C9C.
- Aucun compte, mot de passe, clé, APK, configuration, PCAP ou journal personnel ajouté au dépôt.

Test : cliquer seulement **Comparer RTC IPC** après MAJ et période anti-répétition, puis communiquer le résultat.
