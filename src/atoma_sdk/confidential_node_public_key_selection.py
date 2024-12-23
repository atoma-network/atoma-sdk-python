"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from .basesdk import BaseSDK
from atoma_sdk import models, utils
from atoma_sdk._hooks import HookContext
from atoma_sdk.types import OptionalNullable, UNSET
from atoma_sdk.utils import get_security_from_env
from typing import Any, Mapping, Optional


class ConfidentialNodePublicKeySelection(BaseSDK):
    def select_node_public_key(
        self,
        *,
        model_name: str,
        retries: OptionalNullable[utils.RetryConfig] = UNSET,
        server_url: Optional[str] = None,
        timeout_ms: Optional[int] = None,
        http_headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        r"""Handles requests to select a node's public key for confidential compute operations.

        This endpoint attempts to find a suitable node and retrieve its public key for encryption
        through a two-step process:

        1. First, it tries to select an existing node with a public key directly.
        2. If no node is immediately available, it falls back to finding the cheapest compatible node
        and acquiring a new stack entry for it.

        # Parameters
        - `state`: The shared proxy state containing connections to the state manager and Sui
        - `metadata`: Request metadata from middleware
        - `request`: JSON payload containing the requested model name

        # Returns
        Returns a `Result` containing either:
        - `Json<SelectNodePublicKeyResponse>` with:
        - The selected node's public key (base64 encoded)
        - The node's small ID
        - Optional stack entry digest (if a new stack entry was acquired)
        - `StatusCode` error if:
        - `INTERNAL_SERVER_ERROR` - Communication errors or missing node public keys
        - `SERVICE_UNAVAILABLE` - No nodes available for confidential compute

        # Example Response
        ```json
        {
        \"public_key\": [base64_encoded_bytes],
        \"node_small_id\": 123,
        \"stack_entry_digest\": \"transaction_digest_string\"
        }
        ```

        This endpoint is specifically designed for confidential compute scenarios where
        requests need to be encrypted before being processed by nodes.

        :param model_name: The request model name
        :param retries: Override the default retry configuration for this method
        :param server_url: Override the default server URL for this method
        :param timeout_ms: Override the default request timeout configuration for this method in milliseconds
        :param http_headers: Additional headers to set or replace on requests.
        """
        base_url = None
        url_variables = None
        if timeout_ms is None:
            timeout_ms = self.sdk_configuration.timeout_ms

        if server_url is not None:
            base_url = server_url

        request = models.SelectNodePublicKeyRequest(
            model_name=model_name,
        )

        req = self.build_request(
            method="GET",
            path="/v1/encryption/public-key",
            base_url=base_url,
            url_variables=url_variables,
            request=request,
            request_body_required=True,
            request_has_path_params=False,
            request_has_query_params=True,
            user_agent_header="user-agent",
            accept_header_value="application/json",
            http_headers=http_headers,
            security=self.sdk_configuration.security,
            get_serialized_body=lambda: utils.serialize_request_body(
                request, False, False, "json", models.SelectNodePublicKeyRequest
            ),
            timeout_ms=timeout_ms,
        )

        if retries == UNSET:
            if self.sdk_configuration.retry_config is not UNSET:
                retries = self.sdk_configuration.retry_config

        retry_config = None
        if isinstance(retries, utils.RetryConfig):
            retry_config = (retries, ["429", "500", "502", "503", "504"])

        http_res = self.do_request(
            hook_ctx=HookContext(
                operation_id="select_node_public_key",
                oauth2_scopes=[],
                security_source=get_security_from_env(
                    self.sdk_configuration.security, models.Security
                ),
            ),
            request=req,
            error_status_codes=["4XX", "500", "503", "5XX"],
            retry_config=retry_config,
        )

        if utils.match_response(http_res, "200", "application/json"):
            return utils.unmarshal_json(http_res.text, Any)
        if utils.match_response(http_res, ["4XX", "500", "503", "5XX"], "*"):
            http_res_text = utils.stream_to_text(http_res)
            raise models.APIError(
                "API error occurred", http_res.status_code, http_res_text, http_res
            )

        content_type = http_res.headers.get("Content-Type")
        http_res_text = utils.stream_to_text(http_res)
        raise models.APIError(
            f"Unexpected response received (code: {http_res.status_code}, type: {content_type})",
            http_res.status_code,
            http_res_text,
            http_res,
        )

    async def select_node_public_key_async(
        self,
        *,
        model_name: str,
        retries: OptionalNullable[utils.RetryConfig] = UNSET,
        server_url: Optional[str] = None,
        timeout_ms: Optional[int] = None,
        http_headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        r"""Handles requests to select a node's public key for confidential compute operations.

        This endpoint attempts to find a suitable node and retrieve its public key for encryption
        through a two-step process:

        1. First, it tries to select an existing node with a public key directly.
        2. If no node is immediately available, it falls back to finding the cheapest compatible node
        and acquiring a new stack entry for it.

        # Parameters
        - `state`: The shared proxy state containing connections to the state manager and Sui
        - `metadata`: Request metadata from middleware
        - `request`: JSON payload containing the requested model name

        # Returns
        Returns a `Result` containing either:
        - `Json<SelectNodePublicKeyResponse>` with:
        - The selected node's public key (base64 encoded)
        - The node's small ID
        - Optional stack entry digest (if a new stack entry was acquired)
        - `StatusCode` error if:
        - `INTERNAL_SERVER_ERROR` - Communication errors or missing node public keys
        - `SERVICE_UNAVAILABLE` - No nodes available for confidential compute

        # Example Response
        ```json
        {
        \"public_key\": [base64_encoded_bytes],
        \"node_small_id\": 123,
        \"stack_entry_digest\": \"transaction_digest_string\"
        }
        ```

        This endpoint is specifically designed for confidential compute scenarios where
        requests need to be encrypted before being processed by nodes.

        :param model_name: The request model name
        :param retries: Override the default retry configuration for this method
        :param server_url: Override the default server URL for this method
        :param timeout_ms: Override the default request timeout configuration for this method in milliseconds
        :param http_headers: Additional headers to set or replace on requests.
        """
        base_url = None
        url_variables = None
        if timeout_ms is None:
            timeout_ms = self.sdk_configuration.timeout_ms

        if server_url is not None:
            base_url = server_url

        request = models.SelectNodePublicKeyRequest(
            model_name=model_name,
        )

        req = self.build_request_async(
            method="GET",
            path="/v1/encryption/public-key",
            base_url=base_url,
            url_variables=url_variables,
            request=request,
            request_body_required=True,
            request_has_path_params=False,
            request_has_query_params=True,
            user_agent_header="user-agent",
            accept_header_value="application/json",
            http_headers=http_headers,
            security=self.sdk_configuration.security,
            get_serialized_body=lambda: utils.serialize_request_body(
                request, False, False, "json", models.SelectNodePublicKeyRequest
            ),
            timeout_ms=timeout_ms,
        )

        if retries == UNSET:
            if self.sdk_configuration.retry_config is not UNSET:
                retries = self.sdk_configuration.retry_config

        retry_config = None
        if isinstance(retries, utils.RetryConfig):
            retry_config = (retries, ["429", "500", "502", "503", "504"])

        http_res = await self.do_request_async(
            hook_ctx=HookContext(
                operation_id="select_node_public_key",
                oauth2_scopes=[],
                security_source=get_security_from_env(
                    self.sdk_configuration.security, models.Security
                ),
            ),
            request=req,
            error_status_codes=["4XX", "500", "503", "5XX"],
            retry_config=retry_config,
        )

        if utils.match_response(http_res, "200", "application/json"):
            return utils.unmarshal_json(http_res.text, Any)
        if utils.match_response(http_res, ["4XX", "500", "503", "5XX"], "*"):
            http_res_text = await utils.stream_to_text_async(http_res)
            raise models.APIError(
                "API error occurred", http_res.status_code, http_res_text, http_res
            )

        content_type = http_res.headers.get("Content-Type")
        http_res_text = await utils.stream_to_text_async(http_res)
        raise models.APIError(
            f"Unexpected response received (code: {http_res.status_code}, type: {content_type})",
            http_res.status_code,
            http_res_text,
            http_res,
        )
