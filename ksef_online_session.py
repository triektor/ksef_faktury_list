#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
# KSeF Interactive Session Module
#
"""
KSeF Interactive Session (Sesja interaktywna) implementation.

Supports:
- AES-256-CBC encryption with PKCS#7 padding
- RSA-OAEP key encryption (SHA-256, MGF1 SHA-256)
- Interactive session management (open, send, close)
- Invoice XML submission and verification

Reference: https://api.ksef.mf.gov.pl/docs/v2/index.html#tag/Wysylka-interaktywna
"""

import base64
import hashlib
import secrets
import logging
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

logger = logging.getLogger(__name__)


class EncryptionData:
    """Container for encryption key material."""

    def __init__(self, symmetric_key: bytes = None, initialization_vector: bytes = None):
        """
        Initialize encryption data.

        Args:
            symmetric_key: 256-bit (32 bytes) AES key, auto-generated if None
            initialization_vector: 128-bit (16 bytes) IV, auto-generated if None
        """
        self.symmetric_key = symmetric_key or secrets.token_bytes(32)
        self.initialization_vector = initialization_vector or secrets.token_bytes(16)

    @property
    def cipher_key(self) -> bytes:
        """Get the symmetric key."""
        return self.symmetric_key

    @property
    def cipher_iv(self) -> bytes:
        """Get the initialization vector."""
        return self.initialization_vector


class FileMetadata:
    """Container for file metadata (hash and size)."""

    def __init__(self, file_data: bytes):
        """
        Calculate file metadata.

        Args:
            file_data: File content as bytes
        """
        self.sha256 = hashlib.sha256(file_data).digest()
        self.size = len(file_data)

    @property
    def hash_sha(self) -> str:
        """Get SHA-256 hash as base64."""
        return base64.b64encode(self.sha256).decode('ascii')

    @property
    def file_size(self) -> int:
        """Get file size in bytes."""
        return self.size


class OnlineSessionEncryption:
    """Handle encryption operations for KSeF online sessions."""

    @staticmethod
    def encrypt_invoice_aes256_cbc(invoice_data: bytes, aes_key: bytes, aes_iv: bytes) -> bytes:
        # ... (walidacja długości bez zmian)

        # PKCS#7 padding
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(invoice_data) + padder.finalize()

        # AES-256-CBC encryption
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(aes_iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # ZMIANA: Zwracamy TYLKO ciphertext. 
        # IV został już wysłany przy otwieraniu sesji w payloadzie 'encryption'
        return ciphertext

    @staticmethod
    def decrypt_invoice_aes256_cbc(
        encrypted_data: bytes,
        aes_key: bytes
    ) -> bytes:
        """
        Decrypt invoice XML encrypted with AES-256-CBC.

        Assumes IV is the first 16 bytes of encrypted_data.

        Args:
            encrypted_data: IV + ciphertext (IV is first 16 bytes)
            aes_key: 256-bit AES key

        Returns:
            Decrypted invoice XML bytes

        Raises:
            ValueError: On invalid key length or decryption failure
        """
        if len(aes_key) != 32:
            raise ValueError(f"AES key must be 256 bits (32 bytes), got {len(aes_key)}")
        if len(encrypted_data) < 16:
            raise ValueError(f"Encrypted data too short, must contain IV (16 bytes)")

        aes_iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(aes_iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS#7 padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        invoice_data = unpadder.update(padded_data) + unpadder.finalize()

        return invoice_data

    @staticmethod
    def encrypt_symmetric_key_rsa_oaep(symmetric_key: bytes, public_key_pem: str) -> bytes:
        try:
            # Dodaj nagłówki PEM jeśli ich nie ma (KSeF zwraca czasem sam Base64)
            if "-----BEGIN CERTIFICATE-----" not in public_key_pem:
                public_key_pem = f"-----BEGIN CERTIFICATE-----\n{public_key_pem}\n-----END CERTIFICATE-----"

            # Załaduj certyfikat i wyciągnij klucz publiczny
            cert = x509.load_pem_x509_certificate(public_key_pem.encode(), default_backend())
            public_key = cert.public_key()

            # Szyfrowanie identyczne z Java OAEPWithSHA-256AndMGF1Padding
            encrypted = public_key.encrypt(
                symmetric_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted
        except Exception as e:
            logger.error(f"Szczegółowy błąd szyfrowania RSA: {e}")
            raise ValueError(f"Failed to encrypt symmetric key: {e}")


class OnlineSessionManager:
    """
    Manage KSeF interactive session lifecycle.

    Wraps KSeFClient methods to handle session state and encryption.
    """

    def __init__(self, ksef_client):
        """
        Initialize session manager.

        Args:
            ksef_client: KSeFClient instance (must be authenticated)
        """
        self.ksef_client = ksef_client
        self.session_reference = None
        self.encryption_data = None
        self.encrypted_symmetric_key = None

    def open_session(
        self,
        schema_version: str = '1-0E',  # ← ZMIANA: zamiast 'FA(3)'
        form_code_value: str = 'FA'
    ) -> dict:
        """
        Open new interactive session.

        Args:
            schema_version: Schema version ('FA(2)' or 'FA(3)')
            form_code_value: Form code value (usually 'VAT')

        Returns:
            Session response dict with:
            - referenceNumber: Session unique ID
            - validUntil: Session expiration timestamp

        Raises:
            Exception: On API error
        """
        # Generate encryption material
        self.encryption_data = EncryptionData()
        logger.info(f"Generated AES-256 key and IV for session")
        logger.debug(f"  AES key: {len(self.encryption_data.cipher_key)} bytes")
        logger.debug(f"  IV: {len(self.encryption_data.cipher_iv)} bytes")

        # Encrypt symmetric key with KSeF public key
        try:
            # Pobieramy listę wszystkich certyfikatów
            certs_data = self.ksef_client._make_request('GET', '/security/public-key-certificates')
            
            # Filtrujemy listę
            target_cert = next(
                (c['certificate'] for c in certs_data if 'SymmetricKeyEncryption' in c.get('usage', [])),
                None
            )
            
            if not target_cert:
                raise ValueError("KSeF nie udostępnił certyfikatu SymmetricKeyEncryption")

            # Szyfrujemy klucz AES wybranym certyfikatem
            self.encrypted_symmetric_key = OnlineSessionEncryption.encrypt_symmetric_key_rsa_oaep(
                self.encryption_data.cipher_key,
                target_cert
            )
        except Exception as e:
            logger.error(f"Błąd przygotowania klucza sesji: {e}")
            raise

        # Open session on KSeF
        payload = {
            "formCode": {
                "systemCode": "FA (3)",
                "schemaVersion": "1-0E",  # Hardcoded na razie
                "value": "FA"
            },
            "encryption": {
                "encryptedSymmetricKey": base64.b64encode(self.encrypted_symmetric_key).decode('ascii'),
                "initializationVector": base64.b64encode(self.encryption_data.cipher_iv).decode('ascii')
            }
        }

        logger.info(f"Opening online session (schema: {schema_version}, form: {form_code_value})")
        logger.debug(f"Session payload: {payload}")

        response = self.ksef_client._make_request(
            'POST',
            '/sessions/online',
            data=payload,
            with_session=True
        )

        self.session_reference = response.get('referenceNumber')
        valid_until = response.get('validUntil')

        if not self.session_reference:
            raise ValueError(f"No referenceNumber in session response: {response}")

        logger.info(f"Session opened successfully")
        logger.info(f"  Reference: {self.session_reference}")
        logger.info(f"  Valid until: {valid_until}")

        return response

    def send_invoice(self, invoice_xml: bytes) -> dict:
        """
        Send encrypted invoice to open session.

        Args:
            invoice_xml: Invoice XML as bytes

        Returns:
            Response dict with:
            - referenceNumber: Document reference number
            - processingCode: Status code (100=processing, 200=success)

        Raises:
            ValueError: If session not open
            Exception: On API error
        """
        if not self.session_reference:
            raise ValueError("Session not open. Call open_session() first.")
        if not self.encryption_data:
            raise ValueError("No encryption data. Call open_session() first.")

        logger.info(f"Encrypting invoice ({len(invoice_xml)} bytes)...")

        # Encrypt invoice
        encrypted_invoice = OnlineSessionEncryption.encrypt_invoice_aes256_cbc(
            invoice_xml,
            self.encryption_data.cipher_key,
            self.encryption_data.cipher_iv
        )
        logger.info(f"Invoice encrypted ({len(encrypted_invoice)} bytes)")

        # Calculate metadata
        orig_metadata = FileMetadata(invoice_xml)
        enc_metadata = FileMetadata(encrypted_invoice)

        logger.debug(f"Original invoice SHA-256: {orig_metadata.hash_sha}")
        logger.debug(f"Encrypted invoice SHA-256: {enc_metadata.hash_sha}")

        # Send to session
        payload = {
            "invoiceHash": orig_metadata.hash_sha,
            "invoiceSize": orig_metadata.file_size,
            "encryptedInvoiceHash": enc_metadata.hash_sha,
            "encryptedInvoiceSize": enc_metadata.file_size,
            "encryptedInvoiceContent": base64.b64encode(encrypted_invoice).decode('ascii')
        }

        logger.info(f"Sending invoice to session {self.session_reference}...")
        endpoint = f"/sessions/online/{self.session_reference}/invoices/"
        response = self.ksef_client._make_request(
            'POST',
            endpoint,
            data=payload,
            with_session=True
        )

        doc_ref = response.get('referenceNumber')
        processing_code = response.get('processingCode')

        logger.info(f"Invoice submitted")
        logger.info(f"  Document reference: {doc_ref}")
        logger.info(f"  Processing code: {processing_code}")

        return response

    def close_session(self) -> dict:
        """
        Close interactive session.

        Initiates async generation of collective UPO (Urzędowe Potwierdzenie Odbioru).
        
        Note: If session is in state 415 (processing), KSeF will close it automatically.

        Returns:
            Response dict

        Raises:
            ValueError: If session not open
            Exception: On API error (except state 415 which is OK)
        """
        if not self.session_reference:
            raise ValueError("Session not open. Call open_session() first.")

        logger.info(f"Closing session {self.session_reference}...")
        endpoint = f"/sessions/online/{self.session_reference}/close"
        
        try:
            response = self.ksef_client._make_request(
                'POST',
                endpoint,
                with_session=True
            )
            logger.info(f"Session closed successfully")
            logger.debug(f"Close response: {response}")
            return response
        
        except Exception as e:
            # Status 415 means session is still processing - this is OK
            # KSeF will close it automatically when done
            error_msg = str(e)
            if "415" in error_msg or "przetwarzania" in error_msg.lower():
                logger.info(f"Session is still processing (status 415) - KSeF will close it automatically")
                return {"status": "processing", "message": "Session will close automatically"}
            else:
                # Re-raise other errors
                raise

    def get_session_status(self) -> dict:
        """
        Get current session status.

        Returns:
            Session status dict with:
            - processingCode: Current status (100=processing, 200=complete)
            - status: Detailed status info

        Raises:
            ValueError: If session not open
            Exception: On API error
        """
        if not self.session_reference:
            raise ValueError("Session not open.")

        logger.info(f"Checking session status: {self.session_reference}")
        endpoint = f"/sessions/online/{self.session_reference}"
        response = self.ksef_client._make_request(
            'GET',
            endpoint,
            with_session=True
        )

        processing_code = response.get('processingCode')
        logger.debug(f"Session status: {processing_code}")

        return response
