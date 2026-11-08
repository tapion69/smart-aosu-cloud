# Smart AOSU Cloud 0.8.13-beta10 — écoute MQTT passive C9C autonome

Après un essai beta9, l'offre MQTT utilisait bien le `moto_id` issu du RTC mais n'obtenait aucune réponse SDP. La différence de route de signalisation n'est pas tranchée par le PCAP d'AOSU, chiffré TLS.

La beta10 ajoute un diagnostic volontaire :
- se connecter au broker avec une identité MQTT propre à HA ;
- s'abonner seulement à l'unique canal appareil et au canal utilisateur de signalisation, tous deux dérivés en mémoire ;
- compter les messages entrants pendant 20 secondes pendant l'ouverture du direct officiel dans l'application ;
- ne publier aucune offre et ne conserver ni payloads ni identifiants ; limite d'une observation par dix minutes ;
- ne jamais démarrer si le direct HA est actif.

Les compteurs ne prouvent pas l'identité de la caméra, et une absence de réponse peut simplement venir d'un canal non utilisé ou d'un accès limité. **Aucune modification du moteur vidéo/PTZ, des paquets MQTT existants ou des contrôleurs C5L/H1L.**
