# Smart AOSU Cloud 0.8.13-beta5 — identité C9C (lecture seule)

La C9C autonome externe accepte la configuration RTC mais ne répond pas aux offres SDP : le destinataire Tuya n'a pas été confirmé par identifiant exact. Cette bêta ajoute le bouton **Vérifier identité**, sans nouvelle tentative vidéo.

- Compare en mémoire les serials AOSU et coopUUID avec les champs Tuya connus; renvoie seulement des compteurs et booléens.
- Actualise l'inventaire Tuya seulement après action manuelle, si le cache est absent ou a plus de 10 minutes. Cette actualisation peut réaliser une authentification Tuya chiffrée et des requêtes en lecture seule.
- Distingue « un seul appareil Tuya » et « caméra dont l'identité a été prouvée ». Aucune adresse, nom, clé, ID ou trame réseau n'est renvoyé.
- Compare les chemins utilisés par C5L et C9C : même méthode de signalisation 302 tentée, mais aucune compatibilité vidéo démontrée sur C9C.
- Ne modifie pas les contrôleurs des C5L et C9C3CA11/H1L ni le mécanisme de négociation vidéo.
- Ne publie pas l'APK Lite ni les ressources OEM.

**Test** : après installation et redémarrage Home Assistant, cliquer **Vérifier identité** et partager uniquement le diagnostic expurgé. Aucun nouvel essai vidéo n'est nécessaire à ce stade.
