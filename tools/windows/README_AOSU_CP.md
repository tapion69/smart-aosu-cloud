# Diagnostic ADB AOSU officiel sans root — Windows

Un seul essai, sans nouveau firmware ni modification de Home Assistant.

1. Télécharger AOSU_CP_SANS_ROOT.ps1 et LANCER_AOSU_CP.cmd dans un même dossier.
2. Connecter un seul téléphone Android par USB avec débogage autorisé.
3. Ouvrir l'application AOSU officielle.
4. Double-cliquer LANCER_AOSU_CP.cmd.
5. Sur le téléphone, ouvrir une seule fois la vidéo de la C9C dans AOSU officiel.
6. Revenir au PC, appuyer sur Entrée et copier uniquement le rapport anonymisé.

ADB est recherché dans PATH et les chemins habituels Android Studio/SDK.
Si absent, installer Android SDK Platform-Tools.

Seules les commandes adb devices, shell pidof et logcat -d sont utilisées.
Le script ne vide pas les journaux, n'installe pas de paquet, ne lit aucun
fichier privé Android, n'envoie aucune commande caméra et ne sauvegarde
aucun journal brut. Les traces ne sont traitées qu'en RAM et la sortie
ne contient que des booléens, jamais les cpDeviceId, secrets ou SN.

Limite importante : une version de production peut ne pas émettre ces logs,
et un marqueur présent peut provenir d'un autre appareil. La lecture ne
prouve ni identité de la C9C ni réussite du flux vidéo.

Le script inclut -SelfTest pour prouver sur des données synthétiques que
les valeurs privées ne sont pas retournées. La CI exécute ce mode sur Windows.

La version HA reste 0.8.13-beta32. Ne pas transmettre de logcat brut.

## Correctif Windows 1.1 — erreur variable HOME

Le script n'utilise plus la variable de boucle \$home, interdite en ecriture
car PowerShell la confond avec \$HOME (variable systeme protegee).
Le test sans telephone execute desormais Find-Adb et verifie que
\$HOME demeure inchange. Tests sur Windows PowerShell 5.1 ET PowerShell 7.
La version Home Assistant 0.8.13-beta32 reste inchangee.

## Correctif Windows 1.2 — diagnostic par étape et parcours ADB simulé

La version 1.1 masquait toutes les erreurs sous un seul texte,
sans dire si la panne venait d'ADB, de l'USB, de l'application
AOSU ou de logcat. La version 1.2 donne maintenant un état précis
pour chaque étape, **sans afficher les erreurs natives** ni un
numéro de série, une valeur cpDeviceId ou une trace brute.

Les commandes ADB sont exécutées dans une fonction dédiée qui
ignore les messages de démarrage du daemon sur stderr en
Windows PowerShell 5.1. Le script reste en lecture seule et
n'enregistre aucun journal. Le test GitHub simule le parcours
complet avec un faux ADB et des identifiants synthétiques,
et vérifie aussi le cas d'un appareil USB non autorisé.
