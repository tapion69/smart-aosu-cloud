# 0.8.13-beta16 — observer le canal d'offre officielle

La bêta15 confirme RTC IPC-v4 et `moto_id` appliqué, mais aucune réponse SDP. L'application officielle produit cependant des réponses et candidats MQTT 302 AES/KCP déchiffrables.

- Étend **Observer MQTT** au canal sortant `smart/mb/out/<appareil>` avec abonnement explicite. Un refus d'abonnement n'interrompt pas les autres observations.
- Compte les offres `302` et la présence anonyme de champs attendus : SDP AES/KCP, source et destination, `sessionid`, `moto_id`, `trace_id`, `path`, `p2p_skill`, `security_level`, préconnexion, tokens.
- Ignore les publications MQTT marquées retained pour éviter de confondre un ancien paquet avec le direct courant.
- Aucun identifiant, SDP, mot de passe, clé ou paquet brut retourné ou enregistré.
- Aucun changement de méthode RTC, moteur vidéo, PTZ C9C, ni des contrôleurs C5L et H1L.

À tester : une seule écoute, ouvrir le direct officiel pendant la fenêtre de 20 secondes, puis transmettre le résultat. Les compteurs sont indicatifs et peuvent être nuls si le broker n'autorise pas cette écoute.
