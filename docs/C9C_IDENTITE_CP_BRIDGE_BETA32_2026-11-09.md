# Pont de référence CP AOSU/Tuya — beta32

Analyse de l'APK AOSU 5.10.12 (17 DEX) : UUIDInfoWebDataItem.coopUUID
alimente GzDeviceInfo.cpDeviceId. TyDeviceCenter lit ce champ
pour le moteur caméra Tuya.

Défaut : AosuCloudClient.refresh utilisait seulement la racine
coopUUID. Le module transport_audit détectait déjà la référence
dans cpDeviceInfo.cpDeviceId sans que le parcours C9C la réutilise.

Correction : lire les trois chemins explicitement autorisés dans
l'unique enregistrement AOSU correspondant au SN C9C autonome.
Refuser tout conflit, valeur invalide ou record ambigu. Le résultat
est une référence privée en RAM, jamais une entité ou un log.
Le diagnostic complet ne renvoie qu'une étiquette de provenance.
La sélection Tuya reste fondée sur une égalité explicite et unique.

La présence d'une référence CP ne garantit pas la vidéo : la
concordance avec l'identifiant Tuya, la signalisation et le SDP
restent à confirmer. Aucun nouvel appel caméra ni SDK créé.
