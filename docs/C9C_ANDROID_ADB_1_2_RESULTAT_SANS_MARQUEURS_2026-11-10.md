# C9C autonome — diagnostic ADB Windows 1.2, 10 novembre 2026

## Résultat réel transmis par l'utilisateur

L'outil `AOSU_CP_SANS_ROOT.ps1` correctif 1.2 est allé au bout
sans erreur après ouverture manuelle de la C9C dans l'application AOSU.

- `ADB_ET_APPLICATION_RECONNUS` : oui.
- `etat = lecture_terminee`.
- `journal_aosu_lisible = true` : signifie seulement qu'au moins une
  ligne a été retournée par `logcat` pour le PID interrogé.
  Le script ne confirme **pas** que cette ligne émane du SDK P2P/Tuya.
- `marqueur_cp_trouve = false`.
- `valeur_cp_potentielle_dans_journal = false`.
- Chargement listes AOSU/Tuya, erreur de liste, rapprochement cache,
  recherche targetCpDeviceId, défaut de correspondance et valeur CP
  nulle : tous les marqueurs testés sont **false**.
- `identite_c9c_tuya_prouvee = false`.
- Rapport uniquement booléen, sans identifiants ou journaux bruts.
- Aucun appel caméra, réveil, MQTT, SDP ni PTZ par le script.

## Conclusion

Le processus Android officiel `com.glazero.android` a été détecté,
mais **aucun des messages de débogage statiquement identifiés dans
l'APK AOSU 5.10.12 n'a été vu dans le tampon logcat accessible**,
en filtrant par PID principal. Les messages peuvent être désactivés
dans cette version de production, appartenir à d'autres processus,
avoir été émis à un autre moment ou avoir été purgés du tampon.

Il serait faux d'en déduire que `cpDeviceId` n'existe pas dans
le cache privé de l'application, ou que la C9C ne prend pas en
charge le moteur Tuya. Ce diagnostic **ne fournit aucune nouvelle
preuve d'identité AOSU/Tuya**.

Les constats précédents restent inchangés : `getList`,
`getInfoBySn`, la fiche Tuya et les trois méthodes RTC
n'ont pas révélé de correspondance exacte ; `p2pType=4`
dans la fiche d'un candidat ne prouve pas que c'est la C9C.

## Prochaine voie raisonnable

Le site AOSU publie une notice d'accès aux données mentionnant
les journaux d'exploitation et les données d'usage de l'application,
avec une procédure de demande à `support@aosulife.com` :
https://www.aosulife.com/pages/data-notice

Une demande par le **propriétaire de la caméra et du compte**
pourrait porter sur les **métadonnées d'appairage AOSU/Tuya de
l'appareil C9C**, y compris l'existence éventuelle d'un
identifiant de coopération/CP, et sur l'accès aux données
techniques associées. Ce document ne suppose **ni** que ces données
sont disponibles **ni** que le fournisseur les communiquera.
Demander une procédure de consultation, idéalement sans envoyer
de secrets, de jetons, de mots de passe ni de journaux bruts.

AOSU documente également une entrée **Feedback** dans
l'application et un menu **À propos** contenant les SN :
https://community.aosulife.com/t/app-manual/213

## Développement

- Ne pas répéter le même diagnostic ADB 1.2 ni recontacter les mêmes
  API sans changement de méthode de preuve.
- Une extension `logcat` à d'autres processus imposerait une
  réévaluation de sa valeur et de la confidentialité ; ne pas
  supposer qu'elle révélera l'ID.
- N'appliquer aucun routage vidéo nouveau tant que la liaison
  AOSU/Tuya n'est pas démontrée.
- Conserver la version installable `0.8.13-beta32` ainsi que
  les trois caméras précédemment validées, leur PTZ et les entités HA.
