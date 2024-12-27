from dataclasses import dataclass
from typing import Optional

@dataclass
class EncryptedResponse:
    ciphertext: str
    salt: str
    nonce: str
    node_dh_public_key: str
    plaintext_body_hash: str

    def to_dict(self):
        return {
            "ciphertext": self.ciphertext,
            "salt": self.salt,
            "nonce": self.nonce,
            "node_dh_public_key": self.node_dh_public_key,
            "plaintext_body_hash": self.plaintext_body_hash
        }

    @staticmethod
    def from_dict(data: dict) -> 'EncryptedResponse':
        return EncryptedResponse(
            ciphertext=data["ciphertext"],
            salt=data["salt"],
            nonce=data["nonce"],
            node_dh_public_key=data["node_dh_public_key"],
            plaintext_body_hash=data["plaintext_body_hash"]
        ) 