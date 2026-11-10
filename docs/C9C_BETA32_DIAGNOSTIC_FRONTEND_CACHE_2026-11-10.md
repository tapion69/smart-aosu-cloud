# Smart AOSU — 10 novembre 2026 — résultat beta32 absent de l'affichage

## Capture utilisateur

L'utilisateur a envoyé la sortie suivante après la publication beta32 :

- En-tête : `DIAGNOSTIC COMPLET BETA31 : diagnostic_complet_termine`
- 5/6 appels Tuya acceptés ; un modèle produit non tenté par absence de version.
- Sélection : `appareil_tuya_unique_sans_categorie_video`.
- SN : absent côté Tuya ; référence AOSU : indisponible ; type P2P : Thing 4.
- Identité exacte : non.
- Trois réponses RTC acceptées, WebRTC/auth/moto_id/ICE/session/AES-KCP/TURN,
  sans MSID.
- **Le nouveau champ `Origine référence AOSU` ne figure pas dans le texte.**

## Audit du code publié

Dans la branche main, `manifest.json` vaut `0.8.13-beta32` et
`api.py` exécute `extract_c9c_cp_reference(standalone[0])`.

Le service `diagnostiquer_c9c_complet_b31` renvoie un champ
`identite.origine_aosu_cp` parmi des libellés fixes. La version de
`frontend/c9c-autonome-b1.js` sur GitHub contient la chaîne
`Origine référence AOSU` dans la méthode `_fullB31()`.

**Erreur d'étiquetage mineure** : le titre
`DIAGNOSTIC COMPLET BETA31` a été conservé dans le frontend
de la beta32, donc le seul titre BETA31 ne démontre pas une
mauvaise installation. **L'absence de l'origine est déterminante** :
le navigateur utilise vraisemblablement un ancien module JS
(ou le serveur sert un ancien fichier). Le service backend beta32
ou sa présence sur le disque utilisateur n'est pas encore vérifié.

## Vérification sans aucun appel Tuya

1. Vérifier que l'installation Home Assistant possède la beta32.
   Redémarrer HA après son installation.
2. Ouvrir directement l'URL du module JS via l'URL de Home Assistant :
   `/smart-aosu/c9c-autonome-b1.js?v=0.8.13-beta32`
   et rechercher la chaîne `Origine référence AOSU`.
   Si elle est absente, le serveur charge un ancien fichier.
3. Si elle est présente, modifier le chemin de **ressource Lovelace**
   dans Paramètres > Tableaux de bord > Ressources pour ajouter
   `?v=0.8.13-beta32` à l'URL du fichier. Fermer les anciens
   onglets Home Assistant, rouvrir et recharger la page (Ctrl+F5).
   Le navigateur doit redéfinir le composant au chargement frais :
   le JS contient un garde `customElements.get(...)` qui
   empêche la nouvelle classe de remplacer une ancienne
   dans une page déjà chargée.
4. **Ne pas refaire le bouton Diagnostic complet** tant que le
   JavaScript chargé ne contient pas la chaîne attendue.
5. Une fois la ressource fraîche, un seul nouveau diagnostic
   (respectant les temporisations) suffit pour interpréter
   `origine_aosu_cp` et l'identité exacte.

Cette vérification ne touche ni à la vidéo, ni au P2P, ni au
PTZ, ni aux trois caméras fonctionnelles. La version installable
reste beta32 et aucune modification du code n'est nécessaire
pour isoler le problème de cache.
