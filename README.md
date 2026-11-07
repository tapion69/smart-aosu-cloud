# Smart AOSU Cloud for Home Assistant

> [!WARNING]
> **EXPERIMENTAL / EXPÉRIMENTAL — NOT READY FOR PUBLIC INSTALLATION**
>
> 🇫🇷 Projet communautaire indépendant, **non officiel et non affilié à AOSU**. La compatibilité est limitée aux matériels testés. Les mises à jour AOSU, du firmware ou de Home Assistant peuvent interrompre la vidéo et le PTZ. **Ne l'utilisez pas comme unique système de sécurité.**
>
> 🇬🇧 Unofficial, independent Home Assistant custom integration. Compatibility is limited to tested equipment and may break after camera, cloud or Home Assistant updates. **Do not rely on it as your sole security or surveillance system.**

## 🇫🇷 Présentation

**Smart AOSU Cloud** vise à intégrer les caméras AOSU compatibles dans Home Assistant, avec vidéo, pilotage PTZ et cartes de tableau de bord adaptées. La vidéo peut fonctionner localement selon la configuration, mais l'initialisation d'une session peut nécessiter une authentification AOSU/Tuya.

### État des compatibilités

| Modèle / configuration | État |
| --- | --- |
| **C5L (Garage)** | Vidéo et PTZ validés sur l'installation de développement |
| **Deux C9C3CA11 avec station H1L** | Vidéo et PTZ validés sur une même installation, sans téléphone ni PC lors du démarrage |
| **Caméra solaire autonome 3 MP, batterie 5 000 mAh, PTZ** | Modèle exact inconnu ; test externe prévu, **non compatible à ce jour par défaut** |
| Autres caméras, autres stations, autres réseaux | **Non validés** |

**Version de référence sur l'installation du développeur : 0.8.10.** Une version **0.9.0 bêta expérimentale** pour installations externes est en préparation. **Aucune release publique installable n'est encore annoncée**. Ne configurez pas HACS à partir de ce dépôt avant la publication explicite d'une release compatible.

### Fonctions validées sur le matériel testé

- Vidéo dans Home Assistant, avec démarrage et arrêt du direct.
- PTZ : directions, arrêt au relâchement et arrêt de sécurité.
- Cartes dédiées : vidéo, plein écran et commandes de mouvement.
- Dépendances éventuelles à AOSU/Tuya pour l'authentification ou la négociation d'une session.

### Installation bêta — prochainement

Lorsqu'une **release installable** sera publiée et annoncée comme telle :

1. Installer HACS dans Home Assistant.
2. Ajouter ce dépôt GitHub comme **dépôt personnalisé → Intégration**.
3. Installer une release compatible, puis redémarrer Home Assistant.
4. Ouvrir **Paramètres → Appareils et services → Ajouter une intégration → Smart AOSU Cloud**.
5. Se connecter **avec son propre compte AOSU** et vérifier le modèle de caméra reconnu.
6. Tester les mouvements PTZ avec précaution et vérifier l'arrêt au relâchement.

Cette procédure est **prévisionnelle**, pas encore validée sur une installation neuve.

### Signaler un problème / participer aux tests

Utilisez les **Issues** GitHub en indiquant uniquement le modèle exact, le type de station éventuelle et les versions de Home Assistant et de l'intégration.

**Ne publiez jamais** mot de passe, jeton, localKey, numéro de série complet, capture PCAP brute, adresse privée, image de caméra ou journal non expurgé. Une caméra peut être physiquement motorisée sans utiliser le même protocole PTZ qu'un modèle déjà compatible.

### Licence

© 2026 **tapion69** — droits réservés sur les contributions originales, sous réserve des droits de tiers.

Le code original détenu par le titulaire des droits est proposé sous **[PolyForm Strict 1.0.0](LICENSE)** : utilisation personnelle non commerciale autorisée, mais **modification et redistribution non autorisées sans permission distincte**. Il s'agit de code **source-available**, **pas d'une licence open source**. Les bibliothèques et composants tiers conservent leurs propres licences. Une licence ne peut pas empêcher matériellement la copie d'un dépôt public.

---

## 🇬🇧 English

**Smart AOSU Cloud** is an experimental and unofficial Home Assistant custom integration for selected AOSU cameras, aiming to provide camera video, PTZ and dashboard cards.

**Confirmed only on one development installation:** AOSU C5L (video and PTZ), plus two C9C3CA11 cameras behind one H1L station (video and PTZ). Other equipment, networks and single-camera H1L deployments remain unverified. A **3 MP solar battery PTZ camera** will be tested separately; its exact model and compatibility are unknown.

**Current status:** 0.8.10 is the known working development baseline. **0.9.0 beta is planned, not yet released or verified for external HACS installations.** Follow this repository's releases for confirmed installation instructions.

**Safety:** This software can fail after firmware, AOSU cloud or Home Assistant changes. Never depend on it as your only home security system. Never post credentials, local keys, complete serial numbers, raw PCAP traces or private camera images in public Issues.

**License:** © 2026 tapion69 for original project contributions. **PolyForm Strict 1.0.0** permits personal noncommercial use but does not grant permission to modify or redistribute. This is source-available, not OSI-approved open source. Third-party components retain their own licensing terms. See [LICENSE](LICENSE).

---

_AOSU, Home Assistant, HACS and other marks belong to their respective owners. No endorsement or affiliation is claimed._
