# C9C — matrice automatisée SDK Android ↔ moteur Python, 11 novembre 2026

## Objet
Poursuite technique de l'audit comparatif de l'APK AOSU 5.10.12
(complet, 17 DEX) et de Smart AOSU Cloud `0.8.13-beta32`.
Un seul outil reproductible sous `tools/aosu_c9c_sdk_python_coverage.py`
compare les **références de méthodes réellement invoquées** dans
le DEX et les fonctionnalités visibles dans le code Python. Il
ne copie, n'exporte et n'exécute aucun code propriétaire Android.

### Confirmé statiquement dans `ThingSmartCameraP2PSync.innerConnect`

Le bytecode `classes6.dex` effectue les appels suivants :
- `CameraInfoBean.getP2pPolicy`
- `CameraInfoBean.getSessionTid`
- `ThingSmartCameraP2PSync.getClientTid`
- `ThingSmartCameraP2PSync.getIPCConfigInfo`
- `ThingSmartCameraP2PSync.checkLanConnect`
- `DeviceBean.isLocalDevice`

Le choix du fournisseur (`CameraConstant.getSdkProvider`) consulte
aussi `DeviceBean.getProductBean`, `ProductBean.getCategory`
et `DeviceBean.getSkills`.

`TyCameraCenter` appelle `IThingIPCCore.createCameraP2P`.
Les bibliothèques `libThingP2PSDK.so` et
`libThingCameraSDK.so` sont effectivement embarquées dans le
split ARM64 de l'archive fournie.

### Comparaison avec Smart AOSU

Le Python :
- construit un SDP AES/KCP dans `tuya_media_bootstrap.py` ;
- fabrique une enveloppe JSON/AES/CRC dans `tuya_mqtt_offer.py` ;
- envoie une `sigQry` protocole 22 avant l'offre 302 ;
- utilise un broker MQTT fixé à `m1.tuyaeu.com:8883` ;
- possède encore dans le sélecteur une voie de repli sur un
  **unique appareil Tuya non identifié**.

La présence de `sigQry` en chaîne littérale est localisée dans
`classes4.dex`, à côté de code lié au retour de signal Wi-Fi,
et **pas** dans `classes6.dex`. Cela ne prouve pas qu'aucune
signalisation équivalente n'est produite par du code natif :
une recherche de chaînes ne constitue pas une preuve négative.

## Limites importantes et décision

La matrice est une **couverture de références**, pas un test de
parité octet par octet avec l'encodeur propriétaire :
aucun vecteur de test SDK officiel n'est encore disponible.
Le rapport garde toujours
`binary_protocol_parity_proven=false`,
`camera_identity_proven=false` et
`ready_for_camera_send=false`.
Ne pas affirmer que l'offre Python est conforme au protocole officiel.

Les données de l'installation externe confirment que l'identité
AOSU↔Tuya reste non démontrée. Les essais DP149, PUBACK et RTC
ne prouvent ni une acceptation d'offre ni un retour SDP.

**Conséquence de développement** : ne pas multiplier les
offres manuelles. Prioriser (a) une source vérifiable d'identité,
(b) la parité des messages et des métadonnées de session, puis
(c) un chemin SDK officiel légalement intégrable ou un protocole
indépendant démontré. Aucun nouvel accès réseau ni test caméra.

Les caméras C5L et C9C3CA11/H1L existantes, leur PTZ et
leurs entités Home Assistant ne sont pas modifiés.
Version Home Assistant maintenue à `0.8.13-beta32`.

Exécution locale (avec l'APK personnel, jamais commité) :

```bash
python tools/aosu_c9c_sdk_python_coverage.py "/chemin/vers/Aosu_5.10.12_21839.apks.apk"
```
