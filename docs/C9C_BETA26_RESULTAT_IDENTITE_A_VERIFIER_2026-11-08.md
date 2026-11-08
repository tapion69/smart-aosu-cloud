# C9C autonome — beta26 : compteurs SDK actifs, toujours aucune SDP

**8 novembre 2026 — résultat observé sur caméra externe.**

## Statut relevé

- Version testée : Smart AOSU Cloud **0.8.13-beta26**.
- RTC IPC-v4 accepté ; méthode de sélection : `appareil_tuya_unique_sans_categorie_video`.
- `moto_id` RTC présent dans la configuration et intégré à l'offre.
- Réveil envoyé, acquitté par broker ; `DP149=true` observé (1).
- Temps de confirmation du réveil : **4 023 ms**.
- Connexion MQTT unique entre réveil et offre : **oui**.
- Offre SDP envoyée et PUBACK du broker : **oui**.
- Nouveau compteur SDK C9C beta26 : **actif**.
- Réponses `sigQry` : **0** ; réponses SDP : **0** ;
  protocole 302 inconnu ou invalide : **0**.
- Messages hors protocole 302 : **37**, tous classés dans la plage 0–99 ;
  **0** correspondent à une origine reconnue comme venant du candidat Tuya.
- Connexion P2P établie : **non** ; images JPEG : **0**.

## Ce que cela prouve et ne prouve pas

La modification S/O a effectivement été activée dans l'intégration, mais
**n'a pas suffi** pour obtenir une réponse SDP. Le PUBACK confirme
l'acceptation par le broker, pas une réception ni un traitement par
la caméra. Les 37 messages d'autres protocoles ne sont pas des réponses
vidéo démontrées.

**Point critique encore ouvert :** `appareil_tuya_unique_sans_categorie_video`
est une **sélection heuristique**, pas une identité confirmée entre
la caméra AOSU et l'appareil Tuya. Le champ `autres provenant appareil=0`
signifie seulement qu'aucune origine n'a été reconnue comme égale à
l'identifiant Tuya sélectionné, et ne certifie pas à lui seul une
mauvaise identité.

## Prochain test prioritaire (sans mise à jour)

Utiliser **Vérifier identité** sur la carte C9C autonome existante.
Relever l'état, les nombres de correspondances série/coopUUID, le champ
`liaison exacte`, `SN=ID Tuya`, la sélection RTC et le fournisseur
P2P déclaré. Aucun démarrage vidéo, MQTT actif ni PTZ ne doit être
déclenché par ce contrôle. Si l'identité n'est pas confirmée, prioriser
la résolution du bon périphérique/ID et du routage AOSU avant une
nouvelle offre 302 ou une beta27.

**Version installable inchangée : 0.8.13-beta26**. Ne pas toucher aux
chemins C5L / C9 derrière H1L validés.
