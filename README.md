# Trans-Decryption

Outils de déchiffrement pour les données chiffrées par [Trans-Cryption](https://trans-cryption.github.io/contact) utilisant RSA + AES.

## Table des matières
- [Vue d'ensemble](#vue-densemble)
- [Architecture du système](#architecture-du-système)
- [Installation commune](#installation-commune)
- [Outil 1 : Déchiffrement simple (decrypt.py)](#outil-1--déchiffrement-simple-decryptpy)
  - [Utilisation](#utilisation-de-decryptpy)
  - [Options](#options-de-decryptpy)
  - [Exemples](#exemples-de-decryptpy)
- [Outil 2 : Processeur d'emails (process_encrypted_emails.py)](#outil-2--processeur-demails-process_encrypted_emailspy)
  - [Configuration pour Gmail](#configuration-pour-gmail)
  - [Utilisation](#utilisation-du-processeur-demails)
  - [Options](#options-du-processeur-demails)
  - [Exemples](#exemples-dutilisation-du-processeur-demails)
- [Sécurité](#remarques-sur-la-sécurité)
- [Automatisation](#automatisation)
- [Dépannage](#dépannage)

## Vue d'ensemble

Ce projet propose deux outils complémentaires pour travailler avec des données chiffrées via le système hybride RSA + AES :

1. **decrypt.py** - Outil de base pour déchiffrer directement des données chiffrées
2. **process_encrypted_emails.py** - Outil avancé pour automatiser la récupération et le déchiffrement d'emails contenant des données chiffrées

Ces outils sont particulièrement adaptés pour traiter les soumissions de formulaires web sécurisés configurés avec la solution Trans-Cryption.

## Architecture du système

### Vue d'ensemble du flux de données

```
+---------------------+        +-----------------------+
| Formulaire web      |        | Serveur email         |
| (Trans-Cryption)    |------->| (Gmail, etc.)         |
+---------------------+        +-----------------------+
         |                               |
         | Chiffrement RSA+AES           | Email avec données chiffrées
         v                               v
+---------------------+        +-----------------------+
| Email chiffré       |        | process_encrypted     |
| (encrypted_data     |------->| _emails.py            |
|  + encrypted_key)   |        | (Récupération IMAP)   |
+---------------------+        +-----------------------+
                                         |
                                         | Extraction des données
                                         v
                              +-----------------------+
                              | decrypt.py            |
                              | (Déchiffrement        |
                              |  RSA + AES)           |
                              +-----------------------+
                                         |
                                         | Données déchiffrées
                                         v
                              +-----------------------+
                              | Fichiers de sortie    |
                              | (.json ou .txt dans   |
                              |  le dossier output)   |
                              +-----------------------+
```

### Fonctionnement détaillé

1. **Chiffrement initial** : Le formulaire web Trans-Cryption chiffre les données utilisateur avec AES, puis chiffre la clé AES avec RSA (clé publique).
   
2. **Transmission par email** : Les données chiffrées sont envoyées par email avec deux éléments :
   - `encrypted_data` : Données du formulaire chiffrées avec AES
   - `encrypted_key` : Clé AES chiffrée avec RSA
   
3. **Récupération des emails** : `process_encrypted_emails.py` se connecte à votre serveur de messagerie via IMAP et extrait les emails contenant des données chiffrées.
   
4. **Déchiffrement** : Les données extraites sont traitées par `decrypt.py` qui :
   - Déchiffre la clé AES à l'aide de votre clé privée RSA
   - Utilise cette clé AES pour déchiffrer les données du formulaire
   
5. **Résultat final** : Les données déchiffrées sont sauvegardées sous forme de fichiers JSON ou texte dans le dossier de sortie.

## Installation commune

### Prérequis

- Python 3.6 ou plus récent
- Bibliothèques requises :
  - cryptography>=38.0.0

### Installation

Clonez le dépôt et installez les dépendances :

```bash
git clone https://github.com/votre-username/trans-decryption.git
cd trans-decryption
pip install -r requirements.txt
```

## Outil 1 : Déchiffrement simple (decrypt.py)

Cet outil permet de déchiffrer directement des données chiffrées avec le système hybride RSA + AES.

### Utilisation de decrypt.py

Commande de base :

```bash
python decrypt.py --data "données_chiffrées" --key "clé_AES_chiffrée" --private-key "chemin_vers_clé_privée"
```

### Options de decrypt.py

| Option | Raccourci | Description |
|--------|-----------|-------------|
| `--data` | `-d` | Données chiffrées (sous forme de chaîne ou chemin vers un fichier) |
| `--key` | `-k` | Clé AES chiffrée avec RSA (sous forme de chaîne ou chemin vers un fichier) |
| `--private-key` | `-p` | Chemin vers le fichier de clé privée RSA |
| `--debug` | `-v` | Active le mode verbose pour le débogage |
| `--output` | `-o` | Fichier de sortie (optionnel) |

### Exemples de decrypt.py

Déchiffrer des données directement depuis la ligne de commande :
```bash
python decrypt.py -d "Salted__xyz123..." -k "ABC123..." -p ./private.pem
```

Déchiffrer des données à partir de fichiers :
```bash
python decrypt.py -d ./data.txt -k ./key.txt -p ./private.pem -o results.json
```

## Outil 2 : Processeur d'emails (process_encrypted_emails.py)

Cet outil vous permet d'automatiser la récupération et le déchiffrement des emails contenant des données chiffrées.

### Configuration pour Gmail

Gmail requiert quelques étapes spécifiques pour l'authentification :

1. **Activer l'accès IMAP** dans vos paramètres Gmail :
   - Connectez-vous à votre compte Gmail
   - Cliquez sur l'icône d'engrenage (paramètres) en haut à droite
   - Sélectionnez "Voir tous les paramètres"
   - Cliquez sur l'onglet "Transfert et POP/IMAP"
   - Activez "Accès IMAP"
   - Enregistrez les modifications

2. **Créer un mot de passe d'application** (nécessaire si vous utilisez l'authentification à deux facteurs) :
   - Allez dans votre [compte Google](https://myaccount.google.com/)
   - Sélectionnez "Sécurité"
   - Dans la section "Connexion à Google", activez "Validation en deux étapes" si ce n'est pas déjà fait
   - Retournez à la page Sécurité
   - Sous "Validation en deux étapes", cliquez sur "Mots de passe des applications"
   - Sélectionnez "Autre (nom personnalisé)" dans le menu déroulant
   - Nommez l'application (ex : "Trans-Decryption")
   - Cliquez sur "Générer"
   - Copiez le mot de passe de 16 caractères généré (à utiliser avec le script)

3. **Autoriser les applications moins sécurisées** (si vous n'utilisez pas l'authentification à deux facteurs) :
   - Allez dans les [paramètres de sécurité](https://myaccount.google.com/lesssecureapps)
   - Activez "Autoriser les applications moins sécurisées"

### Utilisation du processeur d'emails

#### Lister les dossiers disponibles

Pour afficher tous les dossiers/labels disponibles dans votre compte email :

```bash
python process_encrypted_emails.py --server imap.gmail.com --email votre@gmail.com --password "votre-mot-de-passe-d-application" --private-key ./private.pem --list-folders
```

#### Traiter les emails

Pour récupérer et déchiffrer les emails non lus dans la boîte de réception :

```bash
python process_encrypted_emails.py --server imap.gmail.com --email votre@gmail.com --password "votre-mot-de-passe-d-application" --private-key ./private.pem
```

### Options du processeur d'emails

| Option | Raccourci | Description |
|--------|-----------|-------------|
| `--server` | `-s` | Serveur IMAP (ex: imap.gmail.com) |
| `--email` | `-e` | Adresse email |
| `--password` | `-p` | Mot de passe ou mot de passe d'application |
| `--private-key` | `-k` | Chemin vers le fichier de clé privée RSA |
| `--folder` | `-f` | Dossier à traiter (par défaut: INBOX) |
| `--list-folders` | | Lister tous les dossiers/labels disponibles |
| `--limit` | `-l` | Nombre maximum d'emails à traiter (par défaut: tous) |
| `--all` | `-a` | Traiter tous les emails (pas seulement les non lus) |
| `--mark-read` | `-m` | Marquer les emails traités comme lus |
| `--output-dir` | `-o` | Dossier de sortie pour les fichiers déchiffrés (par défaut: ./output) |
| `--verbose` | `-v` | Active le mode verbeux |

### Exemples d'utilisation du processeur d'emails

#### Traiter tous les emails (lus et non lus) dans "Tous les messages" :

```bash
python process_encrypted_emails.py --server imap.gmail.com --email votre@gmail.com --password "votre-mot-de-passe" --private-key ./private.pem --folder "[Gmail]/All Mail" --all
```

#### Traiter les 5 derniers emails non lus et les marquer comme lus :

```bash
python process_encrypted_emails.py --server imap.gmail.com --email votre@gmail.com --password "votre-mot-de-passe" --private-key ./private.pem --limit 5 --mark-read
```

#### Exécuter en mode verbeux avec un dossier de sortie personnalisé :

```bash
python process_encrypted_emails.py --server imap.gmail.com --email votre@gmail.com --password "votre-mot-de-passe" --private-key ./private.pem --verbose --output-dir ./messages_dechiffres
```

## Remarques sur la sécurité

- Ne stockez pas votre mot de passe dans des scripts ou fichiers non chiffrés
- Envisagez de stocker les informations d'authentification dans des variables d'environnement
- Assurez-vous que votre clé privée RSA est stockée de manière sécurisée (permissions restreintes)
- Les données déchiffrées sont potentiellement sensibles, protégez également les fichiers de sortie

## Automatisation

Pour automatiser le traitement régulier des emails, vous pouvez configurer une tâche cron (Linux/Mac) ou une tâche planifiée (Windows).

Exemple de configuration cron pour exécuter le script toutes les heures :

```
0 * * * * cd /chemin/vers/trans-decryption && python process_encrypted_emails.py --server imap.gmail.com --email votre@gmail.com --password "votre-mot-de-passe" --private-key ./private.pem --mark-read
```

## Dépannage

### Erreurs d'authentification avec Gmail

- Vérifiez que vous utilisez bien un "mot de passe d'application" si vous avez activé l'authentification à deux facteurs
- Assurez-vous que l'accès IMAP est activé dans vos paramètres Gmail
- Si vous n'utilisez pas l'authentification à deux facteurs, vérifiez que vous avez autorisé l'accès aux applications moins sécurisées

### Le script ne trouve pas d'emails chiffrés

- Vérifiez que vous cherchez dans le bon dossier (utilisez `--list-folders` pour voir tous les dossiers)
- Assurez-vous que les emails contiennent bien les champs "encrypted_data" et "encrypted_key"
- Utilisez l'option `--all` pour traiter également les emails déjà lus
- Activez le mode verbeux (`--verbose`) pour plus d'informations sur le traitement
