"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from .basesdk import BaseSDK
from .httpclient import AsyncHttpClient, HttpClient
from .sdkconfiguration import SDKConfiguration
from .utils.logger import Logger, get_default_logger
from .utils.retries import RetryConfig
from atoma_sdk import utils
from atoma_sdk._hooks import SDKHooks
from atoma_sdk.chat_completions import ChatCompletions
from atoma_sdk.embeddings import Embeddings
from atoma_sdk.health import Health
from atoma_sdk.image_generations import ImageGenerations
from atoma_sdk.models_ import Models
from atoma_sdk.node_public_address_registration import NodePublicAddressRegistration
from atoma_sdk.types import OptionalNullable, UNSET
import httpx
from typing import Dict, Optional


class AtomaSDK(BaseSDK):
    health: Health
    r"""Health check"""
    node_public_address_registration: NodePublicAddressRegistration
    r"""Node public address registration"""
    chat_completions: ChatCompletions
    r"""Chat completions"""
    embeddings: Embeddings
    r"""OpenAI's API embeddings v1 endpoint"""
    image_generations: ImageGenerations
    r"""OpenAI's API image generations v1 endpoint"""
    models: Models
    r"""Models"""

    def __init__(
        self,
        server_idx: Optional[int] = None,
        server_url: Optional[str] = None,
        url_params: Optional[Dict[str, str]] = None,
        client: Optional[HttpClient] = None,
        async_client: Optional[AsyncHttpClient] = None,
        retry_config: OptionalNullable[RetryConfig] = UNSET,
        timeout_ms: Optional[int] = None,
        debug_logger: Optional[Logger] = None,
    ) -> None:
        r"""Instantiates the SDK configuring it with the provided parameters.

        :param server_idx: The index of the server to use for all methods
        :param server_url: The server URL to use for all methods
        :param url_params: Parameters to optionally template the server URL with
        :param client: The HTTP client to use for all synchronous methods
        :param async_client: The Async HTTP client to use for all asynchronous methods
        :param retry_config: The retry configuration to use for all supported methods
        :param timeout_ms: Optional request timeout applied to each operation in milliseconds
        """
        if client is None:
            client = httpx.Client()

        assert issubclass(
            type(client), HttpClient
        ), "The provided client must implement the HttpClient protocol."

        if async_client is None:
            async_client = httpx.AsyncClient()

        if debug_logger is None:
            debug_logger = get_default_logger()

        assert issubclass(
            type(async_client), AsyncHttpClient
        ), "The provided async_client must implement the AsyncHttpClient protocol."

        if server_url is not None:
            if url_params is not None:
                server_url = utils.template_url(server_url, url_params)

        BaseSDK.__init__(
            self,
            SDKConfiguration(
                client=client,
                async_client=async_client,
                server_url=server_url,
                server_idx=server_idx,
                retry_config=retry_config,
                timeout_ms=timeout_ms,
                debug_logger=debug_logger,
            ),
        )

        hooks = SDKHooks()

        current_server_url, *_ = self.sdk_configuration.get_server_details()
        server_url, self.sdk_configuration.client = hooks.sdk_init(
            current_server_url, self.sdk_configuration.client
        )
        if current_server_url != server_url:
            self.sdk_configuration.server_url = server_url

        # pylint: disable=protected-access
        self.sdk_configuration.__dict__["_hooks"] = hooks

        self._init_sdks()

    def _init_sdks(self):
        self.health = Health(self.sdk_configuration)
        self.node_public_address_registration = NodePublicAddressRegistration(
            self.sdk_configuration
        )
        self.chat_completions = ChatCompletions(self.sdk_configuration)
        self.embeddings = Embeddings(self.sdk_configuration)
        self.image_generations = ImageGenerations(self.sdk_configuration)
        self.models = Models(self.sdk_configuration)

    def __enter__(self):
        return self

    async def __aenter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.sdk_configuration.client is not None:
            self.sdk_configuration.client.close()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.sdk_configuration.async_client is not None:
            await self.sdk_configuration.async_client.aclose()
