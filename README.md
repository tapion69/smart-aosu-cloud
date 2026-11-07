# Smart AOSU Cloud for Home Assistant

> [!WARNING]
> **EXPERIMENTAL / EXPÉRIMENTAL — NOT READY FOR PUBLIC INSTALLATION**
>
> 🇫🇷 Projet communautaire indépendant, non officiel et non affilié à AOSU. La compatibilité est limitée aux matériels testés. Les mises à jour AOSU, du firmware ou de Home Assistant peuvent interrompre la vidéo et le PTZ. Ne l’utilisez pas comme unique système de sécurité.
>
> 🇬🇧 Unofficial, independent Home Assistant custom integration. Compatibility is limited to tested equipment and may break after camera, cloud or Home Assistant updates. Do not rely on it as your sole security or surveillance system.

## 🇫🇷 Présentation

**Smart AOSU Cloud** vise à intégrer certaines caméras AOSU dans Home Assistant, avec vidéo, pilotage PTZ et cartes de tableau de bord. La vidéo peut fonctionner localement selon la configuration, mais l’initialisation d’une session peut nécessiter une authentification AOSU/Tuya.

### État des compatibilités

| Modèle / configuration | État |
| --- | --- |
| **C5L** | Vidéo et PTZ confirmés sur le matériel de développement |
| **Deux C9C3CA11 avec station H1L** | Vidéo et PTZ confirmés sur les deux caméras dans la configuration de développement |
| Caméras, stations ou nombres de caméras différents | Non validés |

**Version de référence sur le matériel de développement : 0.8.10.** Une version bêta expérimentale destinée aux installations externes est en préparation. Aucune release publique installable n’est annoncée. N’installez pas ce dépôt via HACS avant la publication explicite d’une release compatible.

### Fonctions observées sur le matériel testé

- Vidéo dans Home Assistant, avec démarrage et arrêt du direct.
- Cartes dédiées pour la vidéo, le plein écran et les commandes.
- Les trois caméras du matériel de développement (une C5L et deux C9C3CA11 derrière H1L) fonctionnent en vidéo et en PTZ. Cette validation porte sur cette configuration; les autres réseaux, comptes et modèles restent à vérifier.
- L’authentification ou la négociation d’une session peut dépendre d’AOSU/Tuya.

### Essais manuels

Cette version 0.8.10 est une base de développement et **n’est pas prête à l’installation publique**. L’intégration attend des fichiers locaux sous `/config/smart_aosu_cloud/` : `profile.json` et `aosu_vendor_app.apk`. Ils ne sont pas fournis, ne doivent pas être ajoutés au dépôt et doivent provenir de sources que chaque testeur est autorisé à utiliser. La procédure reproductible pour préparer ces fichiers reste à documenter.

Pour une carte C9/H1L, renseignez `ip_station` avec l’adresse de votre propre station. Aucun IP privé de développement n’est intégré par défaut.

### Issues et participation aux tests

Utilisez les Issues GitHub en indiquant seulement le modèle de caméra, le type de station et les versions de Home Assistant et de l’intégration. **Ne publiez jamais** de mot de passe, jeton, localKey, numéro de série complet, capture PCAP brute, adresse privée, image de caméra ou journal non expurgé.

### Licence

© 2026 **tapion69** — droits réservés sur les contributions originales, sous réserve des droits de tiers. Le code original du titulaire est sous **[PolyForm Strict 1.0.0](LICENSE)** : certains usages non commerciaux sont autorisés, mais la modification et la redistribution nécessitent une autorisation distincte. Le projet est source-available, pas open source. Une licence ne peut pas empêcher matériellement la copie d’un dépôt public. Les composants tiers gardent leurs propres licences.

---

## 🇬🇧 English

**Smart AOSU Cloud** is an experimental, unofficial Home Assistant integration for selected AOSU cameras, aiming to provide video, PTZ and dashboard cards. Video may use local transport, while session setup can still require AOSU/Tuya authentication.

### Compatibility

- **C5L:** video and PTZ confirmed on the development equipment.
- **Two C9C3CA11 cameras behind one H1L station:** video and PTZ confirmed on both cameras in the development setup. This validation covers that setup; other networks, accounts and models remain unverified.
- Other camera/station combinations and camera counts are not validated.

Version 0.8.10 is a development baseline. An experimental beta for external installations is being prepared; no public installable release is announced. Do not install through HACS until a compatible release is explicitly published.

This development version expects local `profile.json` and `aosu_vendor_app.apk` files under `/config/smart_aosu_cloud/`. They are not included and must not be committed; each tester must use files they are authorized to use. A reproducible preparation guide is still needed. For C9/H1L cards, configure `ip_station` with your own station address. No developer LAN address is embedded as a default.

Never publish credentials, tokens, local keys, complete serial numbers, raw packet captures, private IP addresses, camera images, or unredacted logs. Do not distribute proprietary AOSU APKs.

**License:** © 2026 tapion69 for original project contributions, subject to third-party rights. PolyForm Strict 1.0.0 allows some noncommercial uses but does not grant permission to modify or redistribute. This is source-available, not open source. See [LICENSE](LICENSE).

_AOSU, Home Assistant, HACS and other marks belong to their respective owners. No endorsement or affiliation is claimed._
