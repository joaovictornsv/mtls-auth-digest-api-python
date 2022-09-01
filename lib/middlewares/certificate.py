import base64
import os
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.base import Certificate


class CertificateValidator:
    def execute(self, headers: dict):
        server_cert = os.environ.get("API_CERTIFICATE")
        client_cert = headers.get("api-certificate")

        if not client_cert:
            raise Exception("Send a certificate", 401)
        if not server_cert:
            raise Exception("No certificate provided for server", 401)

        client_cert_decoded = self.__decode_cert(client_cert)
        server_cert_decoded = self.__decode_cert(server_cert)

        client_finger_print = self.__get_fingerprint(client_cert_decoded)
        server_finger_print = self.__get_fingerprint(server_cert_decoded)

        if client_finger_print != server_finger_print:
            raise Exception("Invalid thumbprint", 401)

        now = datetime.now()

        if (
            now < client_cert_decoded.not_valid_before
            or now > client_cert_decoded.not_valid_after
        ):
            raise Exception("Send a certificate with valid date", 401)

    def __decode_cert(self, cert: str):
        _, cert, _ = pkcs12.load_key_and_certificates(base64.b64decode(cert), b"")
        return cert

    def __get_fingerprint(self, cert: Certificate):
        fingerprint = cert.fingerprint(hashes.SHA1()).hex()
        return fingerprint
