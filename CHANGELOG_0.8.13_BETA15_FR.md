# Smart AOSU Cloud 0.8.13-beta15 — première offre vidéo C9C via RTC IPC-v4

La bêta14 a confirmé `m.ipc.v4.rtc.config.get` avec session média complète sur la caméra C9C autonome externe. Cette version essaie cette méthode **uniquement pour son direct manuel**.

- Sélectionne `m.ipc.v4.rtc.config.get` pour `standalone_c9c_video_test=True`, sans changer la méthode des autres appareils.
- Conserve volontairement inchangés l'offre MQTT/SDP, le transport, le décodeur et le PTZ pour comparer proprement les résultats.
- Retourne uniquement la catégorie `rtc_api_source` dans le diagnostic final et sur la carte C9C.
- Aucun démarrage automatique, aucune commande PTZ sur la C9C, aucune écriture de secret/PCAP.
- La réussite RTC-v4 ne prouve toujours pas la correspondance AOSU/Tuya au niveau de la vidéo ni une session active.

Pour tester : mise à jour HACS, redémarrage Home Assistant, rechargement du navigateur, une seule tentative « Essayer la vidéo », puis « État » et `dernier_resultat`.
