#!/usr/bin/env python3
"""
Email Processor: Outil pour récupérer et déchiffrer les emails chiffrés avec RSA + AES.
"""

import re
import json
import imaplib
import argparse
import logging
from email import message_from_bytes
from email.header import decode_header
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# Import de la classe TransDecryption existante
from decrypt import TransDecryption


class EmailProcessor:
    """Classe pour récupérer et traiter les emails chiffrés"""

    def __init__(
        self,
        imap_server: str,
        email_address: str,
        password: str,
        private_key_path: str,
        output_dir: str = "output",
        mark_as_read: bool = False,
        verbose: bool = False,
    ):
        """
        Initialise le processeur d'emails

        Args:
            imap_server: Serveur IMAP (ex: imap.gmail.com)
            email_address: Adresse email
            password: Mot de passe ou mot de passe d'application
            private_key_path: Chemin vers la clé privée RSA
            output_dir: Répertoire pour stocker les résultats
            mark_as_read: Marquer les emails traités comme lus
            verbose: Activer le mode verbeux
        """
        # Configuration du logger
        self.logger = logging.getLogger("email-processor")
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        # Paramètres
        self.imap_server = imap_server
        self.email_address = email_address
        self.password = password
        self.private_key_path = private_key_path
        self.output_dir = Path(output_dir)
        self.mark_as_read = mark_as_read
        self.verbose = verbose

        # Créer le répertoire de sortie s'il n'existe pas
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialiser le déchiffreur
        self.decryptor = TransDecryption(verbose=verbose)

    def connect(self) -> bool:
        """
        Se connecte au serveur IMAP

        Returns:
            True si la connexion est établie, False sinon
        """
        try:
            self.logger.info(f"Connexion au serveur IMAP {self.imap_server}...")
            self.mail = imaplib.IMAP4_SSL(self.imap_server)
            self.mail.login(self.email_address, self.password)
            self.logger.info("Connexion établie")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la connexion: {e}")
            return False

    def list_folders(self) -> List[str]:
        """
        Liste tous les dossiers/labels disponibles sur le serveur

        Returns:
            Liste des noms de dossiers/labels
        """
        try:
            self.logger.info("Récupération de la liste des dossiers/labels...")
            status, folders = self.mail.list()
            if status != "OK":
                self.logger.error(
                    f"Erreur lors de la récupération des dossiers: {status}"
                )
                return []

            folder_list = []
            for folder in folders:
                # Décode et extrait le nom du dossier
                decoded_folder = folder.decode("utf-8")
                # Le format est typiquement: '(\\HasNoChildren) "/" "[Gmail]/Sent Mail"'
                # Nous voulons extraire la dernière partie entre guillemets
                match = re.search(r'"([^"]+)"$', decoded_folder)
                if match:
                    folder_name = match.group(1)
                    folder_list.append(folder_name)
                    self.logger.debug(f"Dossier trouvé: {folder_name}")

            self.logger.info(f"{len(folder_list)} dossiers/labels trouvés")
            return folder_list

        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des dossiers: {e}")
            return []

    def disconnect(self) -> None:
        """Ferme la connexion IMAP"""
        try:
            self.mail.close()
            self.mail.logout()
            self.logger.info("Déconnexion du serveur IMAP")
        except Exception as e:
            self.logger.error(f"Erreur lors de la déconnexion: {e}")

    def get_email_content(self, msg) -> str:
        """
        Extrait le contenu textuel d'un message email

        Args:
            msg: Le message email

        Returns:
            Le contenu textuel
        """
        content = ""
        if msg.is_multipart():
            # Si le message a plusieurs parties, parcourir chaque partie
            for part in msg.get_payload():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    # Récupérer le contenu de la partie
                    try:
                        charset = part.get_content_charset() or "utf-8"
                        payload = part.get_payload(decode=True)
                        if payload:
                            content += payload.decode(charset, errors="replace")
                    except Exception as e:
                        self.logger.warning(
                            f"Erreur lors de la lecture d'une partie du message: {e}"
                        )
        else:
            # Si le message n'a qu'une seule partie
            try:
                charset = msg.get_content_charset() or "utf-8"
                payload = msg.get_payload(decode=True)
                if payload:
                    content += payload.decode(charset, errors="replace")
            except Exception as e:
                self.logger.warning(f"Erreur lors de la lecture du message: {e}")

        return content

    def extract_encrypted_data(
        self, content: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Extrait les données chiffrées et la clé chiffrée du contenu de l'email

        Args:
            content: Contenu de l'email

        Returns:
            Tuple (données chiffrées, clé chiffrée) ou (None, None) si non trouvé
        """
        # Patterns pour extraire les données et la clé
        data_pattern = r"[Ee]ncrypted_data\s*:?\s*([A-Za-z0-9+/=]+)"
        key_pattern = r"[Ee]ncrypted_key\s*:?\s*([A-Za-z0-9+/=]+)"

        # Recherche des patterns
        data_match = re.search(data_pattern, content)
        key_match = re.search(key_pattern, content)

        encrypted_data = data_match.group(1).strip() if data_match else None
        encrypted_key = key_match.group(1).strip() if key_match else None

        if encrypted_data and encrypted_key:
            self.logger.debug("Données chiffrées et clé extraites avec succès")
        else:
            self.logger.debug("Données chiffrées ou clé non trouvées")

        return encrypted_data, encrypted_key

    def process_email(self, msg_id: str) -> Optional[Dict[str, Any]]:
        """
        Traite un email spécifique

        Args:
            msg_id: ID du message à traiter

        Returns:
            Dictionnaire contenant les données déchiffrées ou None en cas d'échec
        """
        try:
            # Récupérer le message
            self.logger.debug(f"Traitement du message ID: {msg_id}")
            _, data = self.mail.fetch(msg_id, "(RFC822)")
            raw_email = data[0][1]
            msg = message_from_bytes(raw_email)

            # Extraire les informations de l'email
            subject = decode_header(msg.get("Subject", ""))[0][0]
            if isinstance(subject, bytes):
                subject = subject.decode("utf-8", errors="replace")

            sender = msg.get("From", "")
            date = msg.get("Date", "")

            self.logger.info(f"Email trouvé: {subject} de {sender} le {date}")

            # Récupérer le contenu
            content = self.get_email_content(msg)

            # Extraire les données chiffrées
            encrypted_data, encrypted_key = self.extract_encrypted_data(content)

            if encrypted_data and encrypted_key:
                self.logger.info("Données chiffrées trouvées, déchiffrement...")

                # Déchiffrer les données
                decrypted_data = self.decryptor.decrypt_message(
                    encrypted_data, encrypted_key, self.private_key_path
                )

                if decrypted_data:
                    # Essayer de parser en JSON
                    try:
                        data_json = json.loads(decrypted_data)
                        self.logger.info("Déchiffrement réussi (format JSON)")

                        # Créer un fichier de sortie
                        timestamp = (
                            msg.get("Date", "").replace(":", "-").replace(" ", "_")
                        )
                        filename = f"decrypted_{timestamp}.json"
                        output_path = self.output_dir / filename

                        with open(output_path, "w", encoding="utf-8") as f:
                            json.dump(data_json, indent=2, fp=f)

                        self.logger.info(f"Résultat sauvegardé dans {output_path}")

                        # Si demandé, marquer l'email comme lu
                        if self.mark_as_read:
                            self.mail.store(msg_id, "+FLAGS", "\\Seen")
                            self.logger.debug("Email marqué comme lu")

                        return {
                            "subject": subject,
                            "sender": sender,
                            "date": date,
                            "decrypted_data": data_json,
                            "output_file": str(output_path),
                        }

                    except json.JSONDecodeError:
                        # Si ce n'est pas un JSON valide
                        self.logger.info("Déchiffrement réussi (format texte)")

                        # Créer un fichier de sortie
                        timestamp = (
                            msg.get("Date", "").replace(":", "-").replace(" ", "_")
                        )
                        filename = f"decrypted_{timestamp}.txt"
                        output_path = self.output_dir / filename

                        with open(output_path, "w", encoding="utf-8") as f:
                            f.write(decrypted_data)

                        self.logger.info(f"Résultat sauvegardé dans {output_path}")

                        # Si demandé, marquer l'email comme lu
                        if self.mark_as_read:
                            self.mail.store(msg_id, "+FLAGS", "\\Seen")
                            self.logger.debug("Email marqué comme lu")

                        return {
                            "subject": subject,
                            "sender": sender,
                            "date": date,
                            "decrypted_data": decrypted_data,
                            "output_file": str(output_path),
                        }
                else:
                    self.logger.error("Échec du déchiffrement")
            else:
                self.logger.debug("Pas de données chiffrées trouvées dans cet email")

        except Exception as e:
            self.logger.error(f"Erreur lors du traitement de l'email: {e}")

        return None

    def process_inbox(
        self, folder: str = "INBOX", limit: int = None, only_unread: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Traite les emails dans la boîte de réception

        Args:
            folder: Dossier à traiter
            limit: Nombre maximum d'emails à traiter (None pour tous)
            only_unread: Ne traiter que les emails non lus

        Returns:
            Liste des résultats de déchiffrement
        """
        results = []

        try:
            # Sélectionner le dossier
            self.mail.select(folder)

            # Rechercher les emails
            search_criteria = "UNSEEN" if only_unread else "ALL"
            self.logger.info(
                f"Recherche des emails ({search_criteria}) dans {folder}..."
            )

            status, messages = self.mail.search(None, search_criteria)
            if status != "OK":
                self.logger.error(f"Erreur lors de la recherche d'emails: {status}")
                return results

            # Obtenir les IDs des messages
            message_ids = messages[0].split()
            self.logger.info(f"{len(message_ids)} emails trouvés")

            # Limiter le nombre d'emails à traiter si limit est spécifié
            if limit:
                message_ids = message_ids[:limit]

            # Traiter chaque email
            for msg_id in message_ids:
                result = self.process_email(msg_id)
                if result:
                    results.append(result)

            self.logger.info(f"{len(results)} emails déchiffrés avec succès")

        except Exception as e:
            self.logger.error(f"Erreur lors du traitement des emails: {e}")

        return results


def main():
    """Point d'entrée principal du programme"""
    # Définition des arguments de ligne de commande
    parser = argparse.ArgumentParser(
        description="Récupère et déchiffre les emails contenant des données chiffrées avec RSA + AES"
    )
    parser.add_argument(
        "--server", "-s", required=True, help="Serveur IMAP (ex: imap.gmail.com)"
    )
    parser.add_argument("--email", "-e", required=True, help="Adresse email")
    parser.add_argument(
        "--password",
        "-p",
        required=True,
        help="Mot de passe ou mot de passe d'application",
    )
    parser.add_argument(
        "--private-key",
        "-k",
        required=True,
        help="Chemin vers le fichier de clé privée RSA",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="output",
        help="Répertoire pour stocker les résultats",
    )
    parser.add_argument(
        "--folder", "-f", default="INBOX", help="Dossier à traiter (par défaut: INBOX)"
    )
    parser.add_argument(
        "--list-folders",
        action="store_true",
        help="Lister tous les dossiers/labels disponibles",
    )
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=None,
        help="Nombre maximum d'emails à traiter (par défaut: tous)",
    )
    parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Traiter tous les emails (pas seulement les non lus)",
    )
    parser.add_argument(
        "--mark-read",
        "-m",
        action="store_true",
        help="Marquer les emails traités comme lus",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Active le mode verbeux"
    )

    args = parser.parse_args()

    # Configurer le logger
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    # Initialiser le processeur d'emails
    processor = EmailProcessor(
        imap_server=args.server,
        email_address=args.email,
        password=args.password,
        private_key_path=args.private_key,
        output_dir=args.output_dir,
        mark_as_read=args.mark_read,
        verbose=args.verbose,
    )

    # Se connecter au serveur IMAP
    if processor.connect():
        try:
            # Si l'option --list-folders est spécifiée, afficher la liste des dossiers
            if args.list_folders:
                folders = processor.list_folders()
                if folders:
                    print("\nDossiers/Labels disponibles :")
                    for i, folder in enumerate(folders, 1):
                        print(f"{i}. {folder}")
                    print(
                        '\nUtilisez l\'option --folder "NOM_DU_DOSSIER" pour traiter un dossier spécifique.'
                    )
                else:
                    print("Aucun dossier/label trouvé.")
            else:
                # Traiter les emails
                results = processor.process_inbox(
                    folder=args.folder, limit=args.limit, only_unread=not args.all
                )

                # Afficher un résumé
                if results:
                    print("\nRésumé des déchiffrements :")
                    for i, result in enumerate(results, 1):
                        print(f"\n{i}. Email: {result['subject']}")
                        print(f"   De: {result['sender']}")
                        print(f"   Date: {result['date']}")
                        print(f"   Fichier de sortie: {result['output_file']}")
                else:
                    print("\nAucun email déchiffré.")

        finally:
            # Fermer la connexion
            processor.disconnect()
    else:
        print("Impossible de se connecter au serveur IMAP.")


if __name__ == "__main__":
    main()
