"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from .basesdk import BaseSDK
from atoma_sdk import models, utils
from atoma_sdk._hooks import HookContext
from atoma_sdk.types import OptionalNullable, UNSET
from atoma_sdk.utils import eventstreaming, get_security_from_env
from typing import Any, Dict, List, Mapping, Optional, Union

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets


class ConfidentialChat(BaseSDK):
    r"""Atoma's API confidential chat completions v1 endpoint"""

    def create(
        self,
        *,
        messages: Union[
            List[models.ChatCompletionMessage],
            List[models.ChatCompletionMessageTypedDict],
        ],
        model: str,
        frequency_penalty: OptionalNullable[float] = UNSET,
        function_call: Optional[Any] = None,
        functions: OptionalNullable[List[Any]] = UNSET,
        logit_bias: OptionalNullable[Dict[str, float]] = UNSET,
        max_tokens: OptionalNullable[int] = UNSET,
        n: OptionalNullable[int] = UNSET,
        presence_penalty: OptionalNullable[float] = UNSET,
        response_format: Optional[Any] = None,
        seed: OptionalNullable[int] = UNSET,
        stop: OptionalNullable[List[str]] = UNSET,
        stream: OptionalNullable[bool] = False,
        temperature: OptionalNullable[float] = UNSET,
        tool_choice: Optional[Any] = None,
        tools: OptionalNullable[List[Any]] = UNSET,
        top_p: OptionalNullable[float] = UNSET,
        user: OptionalNullable[str] = UNSET,
        retries: OptionalNullable[utils.RetryConfig] = UNSET,
        server_url: Optional[str] = None,
        timeout_ms: Optional[int] = None,
        http_headers: Optional[Mapping[str, str]] = None,
    ) -> models.ChatCompletionResponse:
        r"""Create confidential chat completion

        This handler processes chat completion requests in a confidential manner, providing additional
        encryption and security measures for sensitive data processing. It supports both streaming and
        non-streaming responses while maintaining data confidentiality through AEAD encryption and TEE hardware,
        for full private AI compute.

        :param messages: A list of messages comprising the conversation so far
        :param model: ID of the model to use
        :param frequency_penalty: Number between -2.0 and 2.0. Positive values penalize new tokens based on their existing frequency in the text so far
        :param function_call: Controls how the model responds to function calls
        :param functions: A list of functions the model may generate JSON inputs for
        :param logit_bias: Modify the likelihood of specified tokens appearing in the completion
        :param max_tokens: The maximum number of tokens to generate in the chat completion
        :param n: How many chat completion choices to generate for each input message
        :param presence_penalty: Number between -2.0 and 2.0. Positive values penalize new tokens based on whether they appear in the text so far
        :param response_format: The format to return the response in
        :param seed: If specified, our system will make a best effort to sample deterministically
        :param stop: Up to 4 sequences where the API will stop generating further tokens
        :param stream: Whether to stream back partial progress. Must be false for this request type.
        :param temperature: What sampling temperature to use, between 0 and 2
        :param tool_choice: Controls which (if any) tool the model should use
        :param tools: A list of tools the model may call
        :param top_p: An alternative to sampling with temperature
        :param user: A unique identifier representing your end-user
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

        # TODO: Add error handling
        ################## Our code starts here #########################################################

        chat_completions_request_body = models.CreateChatCompletionRequest(
            frequency_penalty=frequency_penalty,
            function_call=function_call,
            functions=functions,
            logit_bias=logit_bias,
            max_tokens=max_tokens,
            messages=utils.get_pydantic_model(
                messages, List[models.ChatCompletionMessage]
            ),
            model=model,
            n=n,
            presence_penalty=presence_penalty,
            response_format=response_format,
            seed=seed,
            stop=stop,
            stream=stream,
            temperature=temperature,
            tool_choice=tool_choice,
            tools=tools,
            top_p=top_p,
            user=user,
        )

        def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
            # Use HKDF to derive a key from the shared secret
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"encryption-key",
            )
            return hkdf.derive(shared_secret)
        
        def calculate_hash(data: bytes) -> bytes:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(data)
            return digest.finalize()

        # Generate our private key
        private_key = X25519PrivateKey.generate()
    
        # Get our public key
        public_key = private_key.public_key()
        
        # Get node's public key
        res = self.confidential_node_public_key_selection.select_node_public_key(model_name=model)
        public_key_node = res.public_key

        # Generate a random 24-byte salt
        salt = secrets.token_bytes(24)
        
        # Create shared secret using Diffie-Hellman
        shared_secret = private_key.exchange(public_key_node)
        
        # Derive the encryption key using HKDF
        encryption_key = derive_key(shared_secret, salt)
        
        # Create AES-GCM cipher with the derived key
        cipher = AESGCM(encryption_key)
        
        # Generate a random 12-byte nonce
        nonce = secrets.token_bytes(12)
        
        # Serialize the chat completions request body to JSON
        message = chat_completions_request_body.model_dump_json().encode('utf-8')

        # Calculate message hash
        plaintext_body_hash = calculate_hash(message)

        # Encrypt the message
        ciphertext = cipher.encrypt(nonce, message, None)
        
        ##################################################################################################

        request = models.ConfidentialChatCompletionRequest(
            ciphertext=ciphertext,
            client_dh_public_key=public_key,
            nonce=nonce,
            plaintext_body_hash=plaintext_body_hash,
            salt=salt,
        )

        req = self.build_request(
            method="POST",
            path="/v1/confidential/chat/completions",
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
                request, False, False, "json", models.ConfidentialChatCompletionRequest
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
                operation_id="confidential_chat_completions_create",
                oauth2_scopes=[],
                security_source=get_security_from_env(
                    self.sdk_configuration.security, models.Security
                ),
            ),
            request=req,
            error_status_codes=["400", "401", "4XX", "500", "5XX"],
            retry_config=retry_config,
        )

        if utils.match_response(http_res, "200", "application/json"):
            return utils.unmarshal_json(
                http_res.text, models.ConfidentialChatCompletionResponse
            )
        if utils.match_response(http_res, ["400", "401", "4XX", "500", "5XX"], "*"):
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

    async def create_async(
        self,
        *,
        ciphertext: str,
        client_dh_public_key: str,
        nonce: str,
        plaintext_body_hash: str,
        salt: str,
        retries: OptionalNullable[utils.RetryConfig] = UNSET,
        server_url: Optional[str] = None,
        timeout_ms: Optional[int] = None,
        http_headers: Optional[Mapping[str, str]] = None,
    ) -> models.ConfidentialChatCompletionResponse:
        r"""Create confidential chat completion

        This handler processes chat completion requests in a confidential manner, providing additional
        encryption and security measures for sensitive data processing. It supports both streaming and
        non-streaming responses while maintaining data confidentiality through AEAD encryption and TEE hardware,
        for full private AI compute.

        # Arguments

        * `metadata` - Extension containing request metadata including:
        * `endpoint` - The API endpoint being accessed
        * `node_address` - Address of the inference node
        * `node_id` - Identifier of the selected node
        * `num_compute_units` - Available compute units
        * `selected_stack_small_id` - Stack identifier
        * `salt` - Optional salt for encryption
        * `node_x25519_public_key` - Optional public key for encryption
        * `model_name` - Name of the AI model being used
        * `state` - Shared application state (ProxyState)
        * `headers` - HTTP request headers
        * `payload` - The chat completion request body

        # Returns

        Returns a `Result` containing either:
        * An HTTP response with the chat completion result
        * A streaming SSE connection for real-time completions
        * A `StatusCode` error if the request processing fails

        # Errors

        Returns `StatusCode::BAD_REQUEST` if:
        * The 'stream' field is missing or invalid in the payload

        Returns `StatusCode::INTERNAL_SERVER_ERROR` if:
        * The inference service request fails
        * Response processing encounters errors
        * State manager updates fail

        # Security Features

        * Utilizes AEAD encryption for request/response data
        * Supports TEE (Trusted Execution Environment) processing
        * Implements secure key exchange using X25519
        * Maintains confidentiality throughout the request lifecycle

        # Example

        ```rust,ignore
        let response = confidential_chat_completions_handler(
        Extension(metadata),
        State(state),
        headers,
        Json(payload)
        ).await?;
        ```

        :param ciphertext: The encrypted CreateChatCompletionRequest
        :param client_dh_public_key: Client's DH public key for key exchange
        :param nonce: Nonce used for encryption
        :param plaintext_body_hash: Hash of the plaintext body for verification
        :param salt: Salt used for encryption
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

        request = models.ConfidentialChatCompletionRequest(
            ciphertext=ciphertext,
            client_dh_public_key=client_dh_public_key,
            nonce=nonce,
            plaintext_body_hash=plaintext_body_hash,
            salt=salt,
        )

        req = self.build_request_async(
            method="POST",
            path="/v1/confidential/chat/completions",
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
                request, False, False, "json", models.ConfidentialChatCompletionRequest
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
                operation_id="confidential_chat_completions_create",
                oauth2_scopes=[],
                security_source=get_security_from_env(
                    self.sdk_configuration.security, models.Security
                ),
            ),
            request=req,
            error_status_codes=["400", "401", "4XX", "500", "5XX"],
            retry_config=retry_config,
        )

        if utils.match_response(http_res, "200", "application/json"):
            return utils.unmarshal_json(
                http_res.text, models.ConfidentialChatCompletionResponse
            )
        if utils.match_response(http_res, ["400", "401", "4XX", "500", "5XX"], "*"):
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
