# Smart AOSU Cloud 0.8.13-beta7 — fiche C9C autonome

Sur le compte de test externe, `getList` déclare la branche PTZ Ty, mais aucun fournisseur P2P ni type P2P, et l'inventaire Tuya ne fournit pas de modèle ou de référence permettant une correspondance exacte. Le moteur vidéo C5L publie son offre MQTT sans réponse SDP.

Cette version ajoute **Fiche AOSU**, lecture volontaire (au plus une fois par heure) de `/v1/dev/getInfoBySn` pour une C9C autonome unique sans H1L. La réponse est analysée uniquement en mémoire pour identifier les références `cpDeviceId`, `coopUUID` et apparentées, et les comparer aux ID de l'inventaire Tuya. Seuls des booléens et enums autorisés sont retournés. Les champs de fournisseur P2P sont classés sans recopier leur valeur non reconnue.

Aucune vidéo, commande PTZ, capture, secret ni identifiant personnel n'est publié. Le code C5L, les contrôleurs H1L et la sélection RTC demeurent inchangés.

Test chez le frère : mettre à jour, redémarrer HA, forcer le rechargement navigateur, cliquer **Fiche AOSU** une fois, transmettre uniquement le résumé.
