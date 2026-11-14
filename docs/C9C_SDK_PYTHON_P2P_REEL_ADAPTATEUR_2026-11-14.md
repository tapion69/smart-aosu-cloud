# Smart AOSU C9C — véritable moteur P2P Python en adaptateur, pas encore activé

**14 novembre 2026 — PR n° 4, expérimentation isolée. Aucune connexion à la caméra du frère.**

## Décision technique nouvelle

Il existe un SDK Python public **effectivement complet** pour le protocole
Tuya AES/KCP : [roquerodrigo/tuya-ipc-p2p-sdk](https://github.com/roquerodrigo/tuya-ipc-p2p-sdk),
licence MIT, **version 0.1.3** publiée le 8 novembre 2026.

Contrairement à un simple test d'offre MQTT, son
`StreamSession.async_start()` conduit réellement les étapes suivantes :
**MQTT → sigQuery → offre → ICE contrôlé → SDP answer → relais TCP →
offre/candidats relayés → authentification canal 0 → canal KCP vidéo →
déchiffrement JPEG**. Il gère également `async_close()`, qui envoie le
`disconnect` nécessaire pour libérer la session.

Le support déclaré par le projet demeure **alpha**, validé principalement
sur des appareils MJPEG et dans la région américaine. Cela **ne prouve pas**
la compatibilité avec une C9C autonome AOSU en région européenne.

## Nouveaux fichiers

- `c9c_upstream_sdk_bridge.py` : prépare en mémoire un **véritable**
  `StreamConfig` et un `MqttIdentity` du SDK 0.1.3, à partir
  de `PrivateMediaBootstrap`, `TuyaAuthSession` et de l'identité MQTT
  **déjà acquises par Smart AOSU**. Aucune deuxième connexion Smart Life,
  aucun mot de passe supplémentaire et aucune nouvelle lecture RTC.
- Le même adaptateur dispose de
  `run_one_explicit_sdk_session`, qui sait lancer la **vraie**
  `StreamSession` (et non un simulateur de session), écouter ses JPEG,
  puis **fermer systématiquement** le flux et le broker. Il effectue une
  seule tentative, sans reconnexion automatique ; il ne retourne aucun
  identifiant, SDP, mot de passe ou message d'exception du fournisseur.
- `c9c_sdk_safe_signaling.py` : sous-classes isolées
  `SafeAosuMotoClient` et `SafeAosuStreamSession` pour la
  signalisation et le relais propres à l'application AOSU.
  La bibliothèque publique n'est ni modifiée ni copiée dans le dépôt.
- Les nouvelles suites `tests/test_c9c_upstream_sdk_bridge.py` et
  `tests/test_c9c_sdk_safe_signaling.py`, ainsi que
  `.github/workflows/c9c-upstream-sdk-bridge.yml`.

## Sécurité et parité : différences vérifiées du SDK amont

La comparaison **directe du code Python public en version 0.1.3**
a révélé trois différences réelles :

1. Son `MotoClient` construit un contexte `_UNVERIFIED_TLS` sans
   vérifier le certificat ni le hostname du broker. Le dérivé AOSU
   remplace cela par `ssl.create_default_context`, avec
   `CERT_REQUIRED` et `check_hostname=True`. Si le broker refuse
   ce TLS, **aucun repli vers une connexion non vérifiée** n'est admis.
2. Le décodeur de réponse MQTT du SDK écarte les sessions différentes
   **seulement si `sessionid` est présent**, et ne vérifie pas `from/to`.
   Notre dérivé exige **simultanément** `sessionid`, le vrai
   `from=devId` Tuya et `to=uid` de l'utilisateur avant d'émettre un
   callback d'answer/candidate/disconnect. Les charges sont déjà
   déchiffrées avec la clé locale.
3. Le SDK amont écrit `moto_id=""` dans les offres MQTT **et les
   offres relayées**, alors qu'AOSU peut fournir un `moto_id`.
   Les sous-classes prennent seulement la valeur réellement présente
   dans la configuration RTC, la valident, puis la reproduisent dans
   les deux voies. Elles n'inventent jamais un identifiant absent.

Les autres phases (ICE, relay, KCP, déchiffrement média) demeurent
**celles du SDK MIT** ; aucune émulation de l'ABI Android n'est tentée.

## Dépendance volontairement absente de la version installable

Le paquet `tuya-ipc-p2p-sdk==0.1.3` est installé **uniquement dans les
runners GitHub Actions**, où les tests utilisent ses vraies
classes `MqttIdentity`, `StreamConfig`, `MotoClient`,
`StreamSession` et ses encodeurs, avec des **sessions réseau
simulées**. Aucun login, réseau domestique, caméra, propriétaire ou
mot de passe réel n'est touché. Aucun binaire APK original n'est
publié.

**La dépendance n'est PAS ajoutée au `manifest.json` de Home
Assistant ; le code n'est PAS branché au bouton Play**. Le code
actif de la PR sert de fondation et n'est pas installé dans
`main`. Avant de déployer un backend, il faudra également neutraliser
tout logging DEBUG du SDK susceptible de rapporter une référence
de session, un ICE ufrag ou une adresse de candidat.

Tests du pont et de l'adaptation OEM :
https://github.com/tapion69/smart-aosu-cloud/actions/runs/43622328058

## Garde-fous stricts avant un premier vrai test

L'adaptateur refuse la préparation si :

- l'appareil n'est pas une **unique C9C autonome sans H1L** ;
- `AOSU SN` et `Tuya devId` ne sont pas reliés par une **preuve typée
  exacte** venant de deux sources autorisées (la simple unicité ne
  compte pas) ;
- le `devId` retenu n'est pas exactement le destinataire de la
  configuration RTC ;
- la session UID Tuya n'est pas celle qui a fourni la configuration ;
- le RTC est expiré ou dépourvu de clé AES, mot de passe appareil,
  identifiants ICE ou jeton de relais.

En plus, `run_one_explicit_sdk_session` exige une **action Play
explicitement autorisée**, un événement d'arrêt et une configuration
encore fraîche. Il ne fabrique pas de données, ne peut pas renvoyer
une vidéo par un simple `PUBACK`, et ferme la session sur erreur.

La C9C du frère **ne passe pas encore la garde d'identité** :
l'application AOSU Android relie ses fiches via le cache privé
`TyDeviceInfoSource`, mais les réponses AOSU/Tuya déjà obtenues par
Home Assistant ne présentent pas son `cpDeviceId` exact.

## Verdict et prochaine décision

**Le blocage "il faut absolument porter la bibliothèque native Android
sous HA OS" peut désormais être contourné par une voie Python
préexistante, à condition que la caméra utilise ce sous-protocole Tuya.**
C'est un moteur réseau réel, pas seulement une machine d'états.

En revanche, ni la compatibilité de la **C9C autonome particulière**,
ni l'égalité des SDP/jetons avec les SDK AOSU natifs, ni la liaison
AOSU→Tuya ne sont prouvées. Le broker européen peut aussi présenter un
problème TLS ; la vérification ne sera pas désactivée pour "faire marcher".

La prochaine étape utile est **la validation de la correspondance de
l'identité côté AOSU/Tuya**, ou l'obtention d'une interface officielle
donnant ce pont de façon autorisée. Ensuite seulement nous pourrons
raccorder volontairement le backend à Play, avec un unique test
matériel contrôlé et une désinstallation/retour arrière simple.

**`main` reste en `0.8.13-beta44-rc3`, aucune mise à jour
ni essai chez le frère, vidéo/PTZ des trois caméras fonctionnelles
préservés.**
