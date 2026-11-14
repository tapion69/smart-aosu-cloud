# Smart AOSU — ESSAI C9C autonome unique : offre RTC HTTP

**14 novembre 2026 — `0.8.13-beta44-rc1` EXPÉRIMENTALE, branche uniquement**  
Dépôt : https://github.com/tapion69/smart-aosu-cloud/tree/experiment/c9c-one-shot-http-offer

## Pourquoi cet essai est différent des précédents

Le direct C9C autonome n'a jamais renvoyé d'**answer SDP correspondant à l'offre MQTT envoyée par Home Assistant**. Le code Android AOSU 5.10.12 possède aussi une voie native de négociation RTC HTTP, `thing.m.rtc.session.offer_1.0`. La passerelle Java divise cette chaîne en action `thing.m.rtc.session.offer`, version `1.0`, avec le corps structuré en `header` et `msg`.

Cette RC fait **une seule** demande RTC HTTP, sans essayer d'établir un flux vidéo. Elle teste un nouveau maillon concret, plutôt que refaire un PUBACK MQTT déjà observé. **L'acceptation HTTP ne prouve ni la réponse SDP, ni la vidéo, ni une correspondance d'identité certaine.**

## Périmètre et protection

- Exclusivement **une seule caméra C9C autonome sans H1L** dans l'inventaire AOSU de la configuration Home Assistant ciblée.
- Seul candidat Tuya autorisé : une correspondance typée exacte OU **un unique appareil Tuya** sans contradiction ni catégorie explicitement non vidéo, avec confirmation manuelle **distincte** indiquant que son lien au SN AOSU n'est pas encore prouvé.
- RTC `thing.m.rtc.config.get` **fraîche**, dont le `CameraInfoBean.id` est le devId Tuya sélectionné et `p2pSpecifiedType=4`; SDP AES/KCP et clés de relais présentes et validées en RAM.
- Une seule action `thing.m.rtc.session.offer` v1.0 avec un en-tête `offer` et les jetons RTC ; **aucune publication MQTT, DP149, ouverture vidéo, PTZ, enregistrement ou nouvelle APK**.
- Une tentative par heure **dans le processus Home Assistant courant**, sans relance automatique. Un redémarrage réinitialise cette limite en RAM : l'utilisateur doit malgré tout ne faire **qu'un seul essai**. La demande HTTP peut créer un état distant de session ; elle n'est **pas** en lecture seule.
- Les clés, les identifiants, le corps JSON et la réponse brute sont privés ; seuls des booléens et états autorisés sont renvoyés.
- `main` reste en **`0.8.13-beta43`**, chemins vidéo et PTZ C5L/H1L inchangés. RC non destinée à un déploiement stable.

## Installation de l'essai sur l'installation Home Assistant de test

1. Dans l'installation où la **C9C autonome** est déjà configurée, **sauvegarder** le dossier `/config/custom_components/smart_aosu_cloud/` actuellement fonctionnel (bêta43) et la configuration Home Assistant. Ne pas installer cette RC sur une installation de production avec C5L/H1L en cours d'utilisation.
2. Sur GitHub, ouvrir la branche exacte `experiment/c9c-one-shot-http-offer`, puis **Code → Download ZIP**. Dans l'archive, récupérer **uniquement** le dossier `custom_components/smart_aosu_cloud`. Remplacer ce dossier dans `/config/custom_components/` sur **l'instance de test**, puis redémarrer Home Assistant. L'interface en `b43` reste identique ; le service manuel est dans les Outils de développement.
3. Vérifier que le manifeste installé indique **`0.8.13-beta44-rc1`**. Fermer le direct éventuel dans l'application AOSU officielle et ne pas lancer un direct HA simultanément. Vérifier qu'il s'agit bien de l'unique C9C autonome du compte de test.
4. Ouvrir **Outils de développement → Actions**, choisir `smart_aosu_cloud.tester_offre_http_thing4_c9c`, et définir les trois confirmations à `true`. Une version YAML équivalente est donnée ci-dessous.
5. Exécuter **UNE FOIS**. Copier uniquement la réponse expurgée `diagnostic`, `etat`, `requete_http_effectuee`, `serveur_accepte`, `rejet_explicite` et `methode_cible`. Ne partager aucun journal brut, clé, SN, mot de passe, identifiant Tuya, adresse IP, SDP ou capture de trafic.

```yaml
action: smart_aosu_cloud.tester_offre_http_thing4_c9c
data:
  confirmation_camera_c9c_autonome: true
  confirmation_cible_unique_non_prouvee: true
  confirmation_offre_http: true
```

## Interprétation du résultat — un seul diagnostic utile

- `offre_http_test_termine` et `serveur_accepte: true` : Tuya a explicitement accepté la demande HTTP. **Ne prouve pas la vidéo ni l'answer SDP**. Arrêter là ; l'étape suivante devra examiner la réponse native de session sans supposer le flux fonctionnel.
- `offre_http_test_termine` et `rejet_explicite: true` : demande rejetée ; pas de second essai. Chercher une différence de prérequis/format à partir de l'API Java native.
- `offre_http_type4_non_prouve`, `offre_http_cible_non_autorisee`, `offre_http_rtc_incompatible` ou `offre_http_preparation_refusee` : **aucune requête HTTP n'a été envoyée**. Il faut d'abord corriger la conformité du contrat ou l'identité, sans forcer le verrou.
- `erreur_api_tuya` : échec réseau/serveur ; `requete_http_effectuee` peut être vrai même si aucune réponse sûre n'a été obtenue. **Ne pas répéter**, l'état distant peut être inconnu.
- `limite_offre_http_une_heure` : tentative déjà consommée sur le processus courant ; ne pas contourner la limite.

## Revenir à la version précédente

Restaurer **le dossier complet sauvegardé** `smart_aosu_cloud` (bêta43) dans `/config/custom_components/`, puis redémarrer Home Assistant. La branche `main`, les trois caméras historiques et les versions déjà installées ailleurs n'ont pas été modifiées.

## Ce qui a réellement été vérifié

- L'APK OEM fournie par le propriétaire a été inspectée **localement**, et la séparation action/API-version et le corps `setPostData` sont présents dans les DEX originaux. La correspondance réseau de l'offre C9C réelle reste à valider.
- GitHub Actions vérifie la syntaxe de **l'intégration complète**, les sélecteurs, le corps JSON, la protection des secrets et la commande HTTP via **une passerelle simulée sans réseau**.
- Les suites de régression existantes bêta31 et bêta32 sont exécutées sur cette branche.
- Aucun accès à la caméra du frère, aucun état vidéo réel, aucun SDP answer réel n'a été observé par ces tests CI.

**Ceci est le prochain test concret prêt à exécuter sur l'instance C9C de test ; ce n'est pas encore une bêta vidéo fonctionnelle.**
