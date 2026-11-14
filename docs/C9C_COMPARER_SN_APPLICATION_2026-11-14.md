# C9C autonome — comparer le SN affiché dans AOSU à celui reçu par Home Assistant

**Action ajoutée en 0.8.13-beta44-rc2, le 14 novembre 2026.**

Cette action ne concerne que le **numéro de série AOSU**. Elle ne demande pas le numéro de série dans ChatGPT, ni ne l'envoie à Tuya ou GitHub.

## Sur Home Assistant

1. Mettre à jour **Smart AOSU Cloud** vers la version expérimentale `0.8.13-beta44-rc2` depuis le dépôt GitHub géré par Marketplace/HACS, puis **redémarrer Home Assistant**. Si l'intégration a été installée manuellement, elle ne se met pas à jour à partir d'un commit GitHub sans un outil de mise à jour.
2. Dans l'application **AOSU**, ouvrir les informations de la C9C autonome et copier exactement son **SN**.
3. Dans Home Assistant, aller dans **Outils de développement → Actions**, puis choisir **« C9C autonome — comparer le SN de l'application AOSU »**.
4. Coller le SN dans `sn_application_aosu`. **Ne pas publier une capture du formulaire ni copier le SN dans le chat**.
5. Exécuter l'action une seule fois ; transmettre **uniquement les champs `etat`, `sn_aosu_cache_present`, `sn_application_correspond`, `identite_aosu_tuya_etablie_par_ce_test`**, qui ne contiennent aucun numéro de série.

Exemple YAML à remplir dans HA **uniquement**, avec la véritable valeur lue dans l'application :

```yaml
action: smart_aosu_cloud.comparer_sn_application_c9c
data:
  sn_application_aosu: "RECOPIER_LE_SN_ICI"
```

## Interprétation

- `sn_application_egal_aosu` : le SN de l'application AOSU correspond exactement au SN récupéré par l'intégration Home Assistant.
- `sn_application_different_aosu` : le SN saisi ne correspond pas à celui du cache AOSU ; vérifier que l'application et Home Assistant parlent bien de la même caméra/du même compte.
- `sn_aosu_cache_indisponible` : Home Assistant ne connaît pas de SN exploitable pour la caméra C9C autonome ; vérifier la découverte AOSU, pas besoin de relancer l'offre HTTP.
- `sn_application_invalide` : la saisie est vide, tronquée ou contient des caractères invisibles.

**Attention :** une égalité AOSU-appli↔AOSU-Home Assistant n'établit **pas** que l'appareil Tuya candidat est la même caméra. C'est une vérification *préalable*, sans accès réseau, sans action caméra, sans vidéo et sans PTZ. Elle n'explique pas à elle seule le refus HTTP de Tuya en bêta44-rc1.

Le SN est saisi sur le Home Assistant local. L'intégration ne l'enregistre ni ne le journalise, mais d'autres fonctions ou journaux généraux de Home Assistant peuvent conserver une trace des appels de service : éviter les captures d'écran non expurgées et ne pas utiliser d'automatisation pour répéter la commande.
