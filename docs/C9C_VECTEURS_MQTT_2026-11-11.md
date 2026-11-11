# C9C — parité MQTT AES/CRC sur vecteurs publics, 11 novembre 2026

Référence indépendante MIT : `roquerodrigo/tuya-ipc-p2p-sdk`,
`signaling/envelope.py`, `signaling/moto_client.py` et
`tests/test_signaling.py`.

Le test exécute les **fonctions réellement présentes** dans
`tuya_mqtt_offer.py` avec des données entièrement synthétiques,
sans importer Home Assistant et sans envoyer de message.

- Enveloppe `2.2`, CRC32, compteur/source et chiffrement
  AES-ECB PKCS#7 : **octets conformes** au vecteur indépendant.
- Offre ASCII construite par notre `_signal_frame` :
  résultat conforme au vecteur issu de l'encodeur indépendant.
- Unicode : **différence constatée**, notre `ensure_ascii=False`
  contre `json.dumps` par défaut (`ensure_ascii=True`)
  dans la référence ; aucune preuve que cette différence affecte
  la C9C réelle.
- `sigQry` protocole 22 avant 302 : **présent dans
  l'implémentation indépendante**. Le fait de ne trouver la chaîne
  qu'au sein du code Wi-Fi d'AOSU ne justifie PAS sa suppression.

Ces tests ne comparent **pas** les octets d'une capture native AOSU :
la parité du SDK propriétaire, les IDs et la réception du SDP
restent non établis. Ne pas modifier le moteur vidéo maintenant.
Conserver `0.8.13-beta32` et les trois caméras existantes.
