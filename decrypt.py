#!/usr/bin/env python3
"""
Trans-Decryption: Outil de déchiffrement pour les formulaires chiffrés avec RSA + AES.
"""

import json
import base64
import argparse
import logging
from pathlib import Path
from typing import Optional, Union, Dict, Any

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class TransDecryption:
    """Classe principale pour le déchiffrement des données"""

    def __init__(self, verbose: bool = False):
        """
        Initialise le déchiffreur

        Args:
            verbose: Si True, active les logs de débogage
        """
        # Configuration du logger
        self.logger = logging.getLogger("trans-decryption")
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Définir le niveau de log en fonction du mode verbose
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    @staticmethod
    def fix_base64_padding(data: str) -> str:
        """
        Ajoute le padding nécessaire à une chaîne base64 si besoin

        Args:
            data: Chaîne base64 potentiellement sans padding

        Returns:
            Chaîne base64 avec padding correct
        """
        padding_needed = len(data) % 4
        if padding_needed:
            return data + "=" * (4 - padding_needed)
        return data

    @staticmethod
    def read_file_content(file_path: str) -> str:
        """
        Lit le contenu d'un fichier ou retourne la chaîne directement

        Args:
            file_path: Chemin du fichier ou chaîne directe

        Returns:
            Contenu du fichier ou la chaîne d'entrée
        """
        path = Path(file_path)
        if path.is_file():
            return path.read_text().strip()
        return file_path.strip()

    @staticmethod
    def evp_bytes_to_key(
        key: Union[str, bytes], salt: bytes, key_size: int = 32, iv_size: int = 16
    ) -> bytes:
        """
        Implémentation de la fonction de dérivation de clé OpenSSL EVP_BytesToKey

        Args:
            key: Clé d'entrée (chaîne ou bytes)
            salt: Sel pour la dérivation
            key_size: Taille de la clé dérivée
            iv_size: Taille du vecteur d'initialisation

        Returns:
            Clé dérivée et IV concaténés
        """
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        d = b""
        current_hash = b""

        while len(d) < key_size + iv_size:
            md5 = hashes.Hash(hashes.MD5(), backend=default_backend())
            if current_hash:
                md5.update(current_hash)
            md5.update(key_bytes)
            md5.update(salt)
            current_hash = md5.finalize()
            d += current_hash

        return d[: key_size + iv_size]

    def decrypt_aes_cryptojs_format(self, encrypted_data: str, key: str) -> str:
        """
        Déchiffre les données au format CryptoJS AES

        Args:
            encrypted_data: Données chiffrées en base64
            key: Clé AES

        Returns:
            Données déchiffrées en texte

        Raises:
            ValueError: Si le format des données est invalide
        """
        try:
            # Décode les données base64
            self.logger.debug("Décodage des données chiffrées")
            data = base64.b64decode(encrypted_data)

            # Le format CryptoJS commence par "Salted__" suivi de 8 octets de sel
            if data[:8] != b"Salted__":
                raise ValueError("Format CryptoJS invalide, 'Salted__' non trouvé")

            salt = data[8:16]
            ciphertext = data[16:]
            self.logger.debug(f"Sel extrait: {salt.hex()}")
            self.logger.debug(
                f"Longueur des données chiffrées: {len(ciphertext)} octets"
            )

            # Dérive la clé et l'IV à partir de la clé et du sel
            derived = self.evp_bytes_to_key(key, salt)
            key_derived = derived[:32]  # Clé AES-256
            iv = derived[32:48]  # IV de 16 octets
            self.logger.debug(
                f"Clé dérivée (premiers octets): {key_derived[:4].hex()}..."
            )
            self.logger.debug(f"IV dérivé: {iv.hex()}")

            # Déchiffre
            cipher = Cipher(
                algorithms.AES(key_derived), modes.CBC(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            self.logger.debug(
                f"Déchiffrement AES réussi, longueur: {len(decrypted)} octets"
            )

            # Supprime le padding PKCS#7
            padding_length = decrypted[-1]
            self.logger.debug(f"Taille du padding PKCS#7: {padding_length}")

            result = decrypted[:-padding_length].decode("utf-8")
            self.logger.debug("Données déchiffrées avec succès")
            return result

        except Exception as e:
            self.logger.error(f"Erreur lors du déchiffrement AES: {e}")
            raise

    def decrypt_message(
        self, encrypted_data: str, encrypted_key: str, private_key_path: str
    ) -> Optional[str]:
        """
        Déchiffre le message en utilisant le chiffrement hybride RSA + AES

        Args:
            encrypted_data: Données chiffrées ou chemin vers le fichier
            encrypted_key: Clé AES chiffrée ou chemin vers le fichier
            private_key_path: Chemin vers la clé privée RSA

        Returns:
            Données déchiffrées ou None en cas d'erreur
        """
        try:
            # Lit les contenus des fichiers si nécessaire
            self.logger.debug("Lecture des données d'entrée")
            encrypted_data_content = self.read_file_content(encrypted_data)
            encrypted_key_content = self.read_file_content(encrypted_key)

            # Fixe le padding si nécessaire
            encrypted_data_content = self.fix_base64_padding(encrypted_data_content)
            encrypted_key_content = self.fix_base64_padding(encrypted_key_content)

            self.logger.debug(
                f"Longueur des données chiffrées: {len(encrypted_data_content)} caractères"
            )
            self.logger.debug(
                f"Longueur de la clé chiffrée: {len(encrypted_key_content)} caractères"
            )

            # Charge la clé privée
            self.logger.debug(f"Chargement de la clé privée depuis {private_key_path}")
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None, backend=default_backend()
                )

            # Décode la clé chiffrée en base64
            try:
                self.logger.debug("Décodage de la clé chiffrée")
                encrypted_key_bytes = base64.b64decode(encrypted_key_content)
            except Exception as e:
                self.logger.warning(f"Échec du décodage de la clé: {e}")
                self.logger.debug("Tentative de correction des problèmes d'encodage...")

                # Corrige les problèmes d'encodage courants
                encrypted_key_content = (
                    encrypted_key_content.replace("\n", "")
                    .replace("\r", "")
                    .replace(" ", "+")
                )
                encrypted_key_bytes = base64.b64decode(
                    self.fix_base64_padding(encrypted_key_content)
                )
                self.logger.debug("Clé corrigée et décodée avec succès")

            # Déchiffre la clé AES avec RSA
            try:
                self.logger.debug("Déchiffrement de la clé AES avec RSA")
                aes_key = private_key.decrypt(
                    encrypted_key_bytes,
                    padding.PKCS1v15(),
                ).decode("utf-8")
                self.logger.debug("Clé AES déchiffrée avec succès")
            except Exception as e:
                self.logger.error(f"Échec du déchiffrement de la clé AES: {e}")
                raise

            # Déchiffre les données avec la clé AES
            self.logger.debug("Déchiffrement des données avec la clé AES")
            decrypted_data = self.decrypt_aes_cryptojs_format(
                encrypted_data_content, aes_key
            )

            return decrypted_data

        except Exception as main_error:
            self.logger.error(f"ERREUR CRITIQUE: {main_error}")
            return None

    def save_to_file(self, content: str, output_path: str) -> bool:
        """
        Sauvegarde le contenu dans un fichier

        Args:
            content: Contenu à sauvegarder
            output_path: Chemin du fichier de sortie

        Returns:
            True si réussi, False sinon
        """
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            self.logger.info(f"Résultat sauvegardé dans {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde du fichier: {e}")
            return False

    def pretty_print_json(self, json_data: Dict[str, Any]) -> None:
        """
        Affiche les données JSON de manière formatée

        Args:
            json_data: Données JSON à afficher
        """
        print("Données du formulaire déchiffrées:")
        # Affiche chaque paire clé-valeur sur une nouvelle ligne
        for key, value in json_data.items():
            print(f"{key}: {value}")


def main():
    """Point d'entrée principal du programme"""
    # Définition des arguments de ligne de commande
    parser = argparse.ArgumentParser(
        description="Déchiffre les données de formulaires chiffrés avec RSA + AES"
    )
    parser.add_argument(
        "--data",
        "-d",
        required=True,
        help="Données chiffrées (chaîne ou chemin de fichier)",
    )
    parser.add_argument(
        "--key",
        "-k",
        required=True,
        help="Clé AES chiffrée (chaîne ou chemin de fichier)",
    )
    parser.add_argument(
        "--private-key",
        "-p",
        required=True,
        help="Chemin vers le fichier de clé privée RSA",
    )
    parser.add_argument(
        "--output", "-o", help="Chemin du fichier de sortie (optionnel)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Active le mode verbeux"
    )

    args = parser.parse_args()

    # Configure et initialise le déchiffreur
    decryptor = TransDecryption(verbose=args.verbose)

    if args.verbose:
        decryptor.logger.debug("Démarrage du processus de déchiffrement...")

    # Déchiffre le message
    decrypted = decryptor.decrypt_message(args.data, args.key, args.private_key)

    if decrypted:
        try:
            # Essaie de parser en JSON
            data = json.loads(decrypted)
            decryptor.pretty_print_json(data)

            # Sauvegarde le résultat si demandé
            if args.output:
                decryptor.save_to_file(json.dumps(data, indent=2), args.output)

        except json.JSONDecodeError:
            # Si ce n'est pas un JSON valide, affiche comme texte brut
            print("Contenu déchiffré (non-JSON):")
            print(decrypted)

            # Sauvegarde le résultat si demandé
            if args.output:
                decryptor.save_to_file(decrypted, args.output)
    else:
        print("Échec du déchiffrement du message")


if __name__ == "__main__":
    main()
