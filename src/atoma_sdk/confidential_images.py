"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from .basesdk import BaseSDK
from atoma_sdk import crypto_utils, models, utils
from atoma_sdk._hooks import HookContext
from atoma_sdk.types import OptionalNullable, UNSET
from atoma_sdk.utils import get_security_from_env
from typing import Mapping, Optional
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class ConfidentialImages(BaseSDK):
    r"""Atoma's API confidential images v1 endpoint"""

    def generate(
        self,
        *,
        prompt: str,
        model: str,
        n: OptionalNullable[int] = UNSET,
        quality: OptionalNullable[str] = UNSET,
        response_format: OptionalNullable[str] = UNSET,
        size: OptionalNullable[str] = UNSET,
        style: OptionalNullable[str] = UNSET,
        user: OptionalNullable[str] = UNSET,
        retries: OptionalNullable[utils.RetryConfig] = UNSET,
        server_url: Optional[str] = None,
        timeout_ms: Optional[int] = None,
        http_headers: Optional[Mapping[str, str]] = None,
    ) -> models.CreateImageResponse:
        r"""
        :param prompt: The input text for image generation
        :param model: The model name for image generation
        :param n: The number of images to generate
        :param quality: The quality of the generated images
        :param response_format: The response format for the generated images
        :param size: The size of the generated images
        :param style: The style of the generated images
        :param user: The user for the generated images
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

        ################## Our code starts here #########################################################
        # Add encryption
        try:
            image_generation_request_body = models.CreateImageRequest(
                prompt=prompt,
                model=model,
                n=n,
                quality=quality,
                response_format=response_format,
                size=size,
                style=style,
                user=user,
            )

            client_dh_private_key = X25519PrivateKey.generate()

            # Encrypt the message
            node_dh_public_key, salt, encrypted_message = crypto_utils.encrypt_message(
                sdk=self, 
                client_dh_private_key=client_dh_private_key,
                request_body=image_generation_request_body,
                model=model
            )

        except Exception as e:
            raise models.APIError(
                f"Failed to prepare confidential image request: {str(e)}",
                500,
                str(e),
                None
            )
        ##################################################################################################

        request = encrypted_message

        req = self._build_request(
            method="POST",
            path="/v1/confidential/images/generations",
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
                request, False, False, "json", models.ConfidentialComputeRequest
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
                operation_id="confidential_image_generations_create",
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
            ##################################################################################################
            encrypted_response = utils.unmarshal_json(
                http_res.text, models.ConfidentialComputeResponse
            )
            # Decrypt the response
            try:
                decrypted_response = crypto_utils.decrypt_message(
                    client_dh_private_key=client_dh_private_key,
                    node_dh_public_key=node_dh_public_key,
                    salt=salt,
                    encrypted_message=encrypted_response
                )
                return utils.unmarshal_json(
                    decrypted_response.decode('utf-8'), models.CreateImageResponse
                )
            except Exception as e:
                raise models.APIError(
                    f"Failed to decrypt response: {str(e)}",
                    500,
                    str(e),
                    http_res
                )
            ##################################################################################################
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

    async def generate_async(
        self,
        *,
        prompt: str,
        model: str,
        n: OptionalNullable[int] = UNSET,
        quality: OptionalNullable[str] = UNSET,
        response_format: OptionalNullable[str] = UNSET,
        size: OptionalNullable[str] = UNSET,
        style: OptionalNullable[str] = UNSET,
        user: OptionalNullable[str] = UNSET,
        retries: OptionalNullable[utils.RetryConfig] = UNSET,
        server_url: Optional[str] = None,
        timeout_ms: Optional[int] = None,
        http_headers: Optional[Mapping[str, str]] = None,
    ) -> models.CreateImageResponse:
        r"""
        :param prompt: The input text for image generation
        :param model: The model name for image generation
        :param n: The number of images to generate
        :param quality: The quality of the generated images
        :param response_format: The response format for the generated images
        :param size: The size of the generated images
        :param style: The style of the generated images
        :param user: The user for the generated images
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

        ################## Our code starts here #########################################################
        # Add encryption
        try:
            image_generation_request_body = models.CreateImageRequest(
                prompt=prompt,
                model=model,
                n=n,
                quality=quality,
                response_format=response_format,
                size=size,
                style=style,
                user=user,
            )

            client_dh_private_key = X25519PrivateKey.generate()

            # Encrypt the message
            node_dh_public_key, salt, encrypted_message = crypto_utils.encrypt_message(
                sdk=self, 
                client_dh_private_key=client_dh_private_key,
                request_body=image_generation_request_body,
                model=model
            )

        except Exception as e:
            raise models.APIError(
                f"Failed to prepare confidential image request: {str(e)}",
                500,
                str(e),
                None
            )
        ##################################################################################################

        request = encrypted_message

        req = self._build_request_async(
            method="POST",
            path="/v1/confidential/images/generations",
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
                request, False, False, "json", models.ConfidentialComputeRequest
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
                operation_id="confidential_image_generations_create",
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
            ##################################################################################################
            encrypted_response = utils.unmarshal_json(
                http_res.text, models.ConfidentialComputeResponse
            )
            # Decrypt the response
            try:
                decrypted_response = crypto_utils.decrypt_message(
                    client_dh_private_key=client_dh_private_key,
                    node_dh_public_key=node_dh_public_key,
                    salt=salt,
                    encrypted_message=encrypted_response
                )
                return utils.unmarshal_json(
                    decrypted_response.decode('utf-8'), models.CreateImageResponse
                )
            except Exception as e:
                raise models.APIError(
                    f"Failed to decrypt response: {str(e)}",
                    500,
                    str(e),
                    http_res
                )
            ##################################################################################################
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
