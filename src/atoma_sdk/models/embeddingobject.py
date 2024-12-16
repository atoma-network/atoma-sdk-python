"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from atoma_sdk.types import BaseModel
from typing import List
from typing_extensions import TypedDict


class EmbeddingObjectTypedDict(TypedDict):
    r"""Individual embedding object in the response"""

    embedding: List[float]
    r"""The embedding vector"""
    index: int
    r"""Index of the embedding in the list of embeddings"""
    object: str
    r"""The object type, which is always \"embedding\" """


class EmbeddingObject(BaseModel):
    r"""Individual embedding object in the response"""

    embedding: List[float]
    r"""The embedding vector"""

    index: int
    r"""Index of the embedding in the list of embeddings"""

    object: str
    r"""The object type, which is always \"embedding\" """
