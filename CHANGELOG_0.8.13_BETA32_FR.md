# Smart AOSU Cloud 0.8.13-beta32

Correction étroite de l'extraction CP depuis l'inventaire AOSU
de la C9C autonome, sur trois chemins connus : coopUUID,
cpDeviceId et cpDeviceInfo.cpDeviceId. Lien exact uniquement si
les champs présents sont valides et concordants, puis comparés
à un unique appareil Tuya. Les données privées ne sont ni
affichées ni enregistrées.

Diagnostic complet affiche une étiquette neutre « Origine référence
AOSU » pour éviter les nouveaux tests individuels. L'ancien
bouton, le nombre de lectures, les limites de fréquence, les
moteurs C5L/H1L, la vidéo et le PTZ restent inchangés.
Tests hors ligne et contrôle GitHub Actions ajoutés.
