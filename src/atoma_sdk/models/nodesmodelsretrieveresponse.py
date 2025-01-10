"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from atoma_sdk.types import BaseModel, Nullable, OptionalNullable, UNSET, UNSET_SENTINEL
from pydantic import model_serializer
from typing import List
from typing_extensions import NotRequired, TypedDict


class NodesModelsRetrieveResponseTypedDict(TypedDict):
    r"""The response body for selecting a node's public key for encryption
    from a client. The client will use the provided public key to encrypt
    the request and send it back to the proxy. The proxy will then route this
    request to the selected node.
    """

    node_small_id: int
    r"""The node small id for the selected node"""
    public_key: List[int]
    r"""The public key for the selected node, base64 encoded"""
    stack_small_id: int
    r"""The stack small id to which an available stack entry was acquired, for the selected node"""
    stack_entry_digest: NotRequired[Nullable[str]]
    r"""Transaction digest for the transaction that acquires the stack entry, if any"""


class NodesModelsRetrieveResponse(BaseModel):
    r"""The response body for selecting a node's public key for encryption
    from a client. The client will use the provided public key to encrypt
    the request and send it back to the proxy. The proxy will then route this
    request to the selected node.
    """

    node_small_id: int
    r"""The node small id for the selected node"""

    public_key: List[int]
    r"""The public key for the selected node, base64 encoded"""

    stack_small_id: int
    r"""The stack small id to which an available stack entry was acquired, for the selected node"""

    stack_entry_digest: OptionalNullable[str] = UNSET
    r"""Transaction digest for the transaction that acquires the stack entry, if any"""

    @model_serializer(mode="wrap")
    def serialize_model(self, handler):
        optional_fields = ["stack_entry_digest"]
        nullable_fields = ["stack_entry_digest"]
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