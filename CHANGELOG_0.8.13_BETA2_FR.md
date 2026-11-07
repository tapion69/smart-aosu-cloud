# Smart AOSU Cloud 0.8.13-beta2 — correction d’identification C9C autonome

## Correction ciblée après le premier test chez un autre utilisateur

- La 0.8.13-beta1 s’arrêtait avant RTC avec `rtc_non_lance_c9c_non_identifiee` ; aucun paquet vidéo n’avait été reçu.
- Une correspondance forte sur les identifiants AOSU/Tuya reste prioritaire.
- Pour une **seule C9C autonome** déjà validée dans l’inventaire AOSU, un essai manuel vidéo peut maintenant choisir **l’unique appareil Tuya catégorisé caméra**, même si le compte Tuya comporte d’autres types d’appareils. Si plusieurs caméras Tuya existent ou aucune caméra n’est reconnue, l’essai est toujours bloqué ; ni nom utilisateur ni ordre des appareils ne servent à choisir.
- Le statut donne désormais le motif exact de refus, le nombre total d’appareils Tuya et le nombre de caméras reconnues, **sans jamais exposer de numéro de série, nom, IP, clé, mot de passe ou jeton**.
- La carte expérimentale affiche le diagnostic utile en bas après « État ».
- Aucun changement aux contrôleurs vidéo/PTZ des C5L et des C9 sur H1L. PTZ **toujours désactivé** pour la C9C autonome.

Cette version ne valide pas encore le protocole C5L sur la C9C ; le test réel reste à faire. Les tentatives répétées sans diagnostic sont déconseillées.
