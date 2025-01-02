"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from atoma_sdk.types import BaseModel, Nullable, OptionalNullable, UNSET, UNSET_SENTINEL
from pydantic import model_serializer
from typing_extensions import NotRequired, TypedDict


class ConfidentialComputeRequestTypedDict(TypedDict):
    r"""A request for confidential computation that includes encrypted data and associated cryptographic parameters"""

    ciphertext: str
    r"""The encrypted payload that needs to be processed (base64 encoded)"""
    client_dh_public_key: str
    r"""Client's public key for Diffie-Hellman key exchange (base64 encoded)"""
    model_name: str
    r"""Model name"""
    node_dh_public_key: str
    r"""Node's public key for Diffie-Hellman key exchange (base64 encoded)"""
    nonce: str
    r"""Cryptographic nonce used for encryption (base64 encoded)"""
    plaintext_body_hash: str
    r"""Hash of the original plaintext body for integrity verification (base64 encoded)"""
    salt: str
    r"""Salt value used in key derivation (base64 encoded)"""
    stack_small_id: int
    r"""Unique identifier for the small stack being used"""
    num_compute_units: NotRequired[Nullable[int]]
    r"""Number of compute units to be used for the request, for image generations,
    as this value is known in advance (the number of pixels to generate)
    """
    stream: NotRequired[Nullable[bool]]
    r"""Indicates whether this is a streaming request"""


class ConfidentialComputeRequest(BaseModel):
    r"""A request for confidential computation that includes encrypted data and associated cryptographic parameters"""

    ciphertext: str
    r"""The encrypted payload that needs to be processed (base64 encoded)"""

    client_dh_public_key: str
    r"""Client's public key for Diffie-Hellman key exchange (base64 encoded)"""

    model_name: str
    r"""Model name"""

    node_dh_public_key: str
    r"""Node's public key for Diffie-Hellman key exchange (base64 encoded)"""

    nonce: str
    r"""Cryptographic nonce used for encryption (base64 encoded)"""

    plaintext_body_hash: str
    r"""Hash of the original plaintext body for integrity verification (base64 encoded)"""

    salt: str
    r"""Salt value used in key derivation (base64 encoded)"""

    stack_small_id: int
    r"""Unique identifier for the small stack being used"""

    num_compute_units: OptionalNullable[int] = UNSET
    r"""Number of compute units to be used for the request, for image generations,
    as this value is known in advance (the number of pixels to generate)
    """

    stream: OptionalNullable[bool] = UNSET
    r"""Indicates whether this is a streaming request"""

    @model_serializer(mode="wrap")
    def serialize_model(self, handler):
        optional_fields = ["num_compute_units", "stream"]
        nullable_fields = ["num_compute_units", "stream"]
        null_default_fields = []

        serialized = handler(self)

        m = {}

        for n, f in self.model_fields.items():
            k = f.alias or n
            val = serialized.get(k)
            serialized.pop(k, None)

            optional_nullable = k in optional_fields and k in nullable_fields
            is_set = (
                self.__pydantic_fields_set__.intersection({n})
                or k in null_default_fields
            )  # pylint: disable=no-member

            if val is not None and val != UNSET_SENTINEL:
                m[k] = val
            elif val != UNSET_SENTINEL and (
                not k in optional_fields or (optional_nullable and is_set)
            ):
                m[k] = val

        return m