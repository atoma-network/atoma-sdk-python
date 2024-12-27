from dataclasses import dataclass
from typing import Optional

@dataclass
class EncryptedRequest:
    ciphertext: str
    salt: str
    nonce: str
    client_dh_public_key: str
    plaintext_body_hash: str

    def to_dict(self):
        return {
            "ciphertext": self.ciphertext,
            "salt": self.salt,
            "nonce": self.nonce,
            "client_dh_public_key": self.client_dh_public_key,
            "plaintext_body_hash": self.plaintext_body_hash
        }

    @staticmethod
    def from_dict(data: dict) -> 'EncryptedRequest':
        return EncryptedRequest(
            ciphertext=data["ciphertext"],
            salt=data["salt"],
            nonce=data["nonce"],
            client_dh_public_key=data["client_dh_public_key"],
            plaintext_body_hash=data["plaintext_body_hash"]
        ) 