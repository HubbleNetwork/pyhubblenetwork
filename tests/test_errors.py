"""Tests for errors.py exception hierarchy."""

from __future__ import annotations

import pytest

from hubblenetwork.errors import (
    HubbleError,
    BackendError,
    RequestError,
    InternalServerError,
    NetworkError,
    APITimeout,
    InvalidCredentialsError,
    ValidationError,
    ScanError,
    DecryptionError,
    InvalidDeviceError,
    ElfFetchError,
    FlashError,
    map_http_status,
    raise_for_response,
)


class TestExceptionHierarchy:
    """Tests for exception class hierarchy."""

    def test_hubble_error_is_base(self):
        """Test HubbleError is base exception."""
        err = HubbleError("test error")
        assert isinstance(err, Exception)
        assert str(err) == "test error"

    def test_backend_error_inherits_from_hubble_error(self):
        """Test BackendError inherits from HubbleError."""
        err = BackendError("backend error")
        assert isinstance(err, HubbleError)
        assert isinstance(err, Exception)

    def test_request_error_inherits_from_backend_error(self):
        """Test RequestError inherits from BackendError."""
        err = RequestError("request error")
        assert isinstance(err, BackendError)
        assert isinstance(err, HubbleError)

    def test_internal_server_error_inherits_from_backend_error(self):
        """Test InternalServerError inherits from BackendError."""
        err = InternalServerError("server error")
        assert isinstance(err, BackendError)

    def test_network_error_inherits_from_backend_error(self):
        """Test NetworkError inherits from BackendError."""
        err = NetworkError("network error")
        assert isinstance(err, BackendError)

    def test_api_timeout_inherits_from_backend_error(self):
        """Test APITimeout inherits from BackendError."""
        err = APITimeout("timeout error")
        assert isinstance(err, BackendError)

    def test_invalid_credentials_error_inherits_from_backend_error(self):
        """Test InvalidCredentialsError inherits from BackendError."""
        err = InvalidCredentialsError("invalid creds")
        assert isinstance(err, BackendError)

    def test_validation_error_inherits_from_backend_error(self):
        """Test ValidationError inherits from BackendError."""
        err = ValidationError("validation error")
        assert isinstance(err, BackendError)

    def test_scan_error_inherits_from_hubble_error(self):
        """Test ScanError inherits from HubbleError (not BackendError)."""
        err = ScanError("scan failed")
        assert isinstance(err, HubbleError)
        assert not isinstance(err, BackendError)

    def test_decryption_error_inherits_from_hubble_error(self):
        """Test DecryptionError inherits from HubbleError (not BackendError)."""
        err = DecryptionError("decrypt failed")
        assert isinstance(err, HubbleError)
        assert not isinstance(err, BackendError)

    def test_invalid_device_error_inherits_from_hubble_error(self):
        """Test InvalidDeviceError inherits from HubbleError."""
        err = InvalidDeviceError("invalid device")
        assert isinstance(err, HubbleError)

    def test_elf_fetch_error_is_runtime_error(self):
        """Test ElfFetchError inherits from RuntimeError."""
        err = ElfFetchError("fetch failed")
        assert isinstance(err, RuntimeError)
        assert not isinstance(err, HubbleError)

    def test_flash_error_is_runtime_error(self):
        """Test FlashError inherits from RuntimeError."""
        err = FlashError("flash failed")
        assert isinstance(err, RuntimeError)
        assert not isinstance(err, HubbleError)


class TestMapHttpStatus:
    """Tests for map_http_status function."""

    def test_400_returns_request_error(self):
        """Test 400 status returns RequestError."""
        err = map_http_status(400)
        assert isinstance(err, RequestError)
        assert "400" in str(err)
        assert "unexpected response" in str(err)

    def test_400_with_detail(self):
        """Test 400 status with detail message."""
        err = map_http_status(400, "Invalid input")
        assert isinstance(err, RequestError)
        assert "400" in str(err)
        assert "Invalid input" in str(err)

    def test_500_returns_internal_server_error(self):
        """Test 500 status returns InternalServerError."""
        err = map_http_status(500)
        assert isinstance(err, InternalServerError)
        assert "500" in str(err)

    def test_500_with_detail(self):
        """Test 500 status with detail message."""
        err = map_http_status(500, "Database error")
        assert isinstance(err, InternalServerError)
        assert "Database error" in str(err)

    def test_other_status_returns_backend_error(self):
        """Test other status codes return generic BackendError."""
        for status in [401, 403, 404, 502, 503]:
            err = map_http_status(status)
            assert isinstance(err, BackendError)
            assert str(status) in str(err)

    def test_none_detail(self):
        """Test with None detail uses default message."""
        err = map_http_status(400, None)
        assert "unexpected response" in str(err)


class TestRaiseForResponse:
    """Tests for raise_for_response function."""

    def test_raises_request_error_for_400(self):
        """Test raises RequestError for 400 status."""
        with pytest.raises(RequestError) as exc_info:
            raise_for_response(400)
        assert "400" in str(exc_info.value)

    def test_raises_internal_server_error_for_500(self):
        """Test raises InternalServerError for 500 status."""
        with pytest.raises(InternalServerError) as exc_info:
            raise_for_response(500)
        assert "500" in str(exc_info.value)

    def test_extracts_error_from_dict_body(self):
        """Test extracts error message from dict body."""
        with pytest.raises(BackendError) as exc_info:
            raise_for_response(400, body={"error": "Bad request"})
        assert "Bad request" in str(exc_info.value)

    def test_extracts_message_from_dict_body(self):
        """Test extracts message from dict body."""
        with pytest.raises(BackendError) as exc_info:
            raise_for_response(400, body={"message": "Invalid parameter"})
        assert "Invalid parameter" in str(exc_info.value)

    def test_extracts_detail_from_dict_body(self):
        """Test extracts detail from dict body."""
        with pytest.raises(BackendError) as exc_info:
            raise_for_response(400, body={"detail": "Missing field"})
        assert "Missing field" in str(exc_info.value)

    def test_extracts_error_description_from_dict_body(self):
        """Test extracts error_description from dict body (highest priority)."""
        with pytest.raises(BackendError) as exc_info:
            raise_for_response(
                400,
                body={
                    "error_description": "Primary error",
                    "error": "Secondary error",
                },
            )
        assert "Primary error" in str(exc_info.value)

    def test_uses_string_body(self):
        """Test uses string body as detail."""
        with pytest.raises(BackendError) as exc_info:
            raise_for_response(400, body="Plain text error")
        assert "Plain text error" in str(exc_info.value)

    def test_strips_whitespace_from_string_body(self):
        """Test strips whitespace from string body."""
        with pytest.raises(BackendError) as exc_info:
            raise_for_response(400, body="  error with spaces  ")
        assert "error with spaces" in str(exc_info.value)

    def test_uses_default_message_when_no_detail(self):
        """Test uses default_message when body provides no detail."""
        with pytest.raises(BackendError) as exc_info:
            raise_for_response(400, body=None, default_message="Default error")
        assert "Default error" in str(exc_info.value)

    def test_uses_default_message_with_empty_dict(self):
        """Test uses default_message when dict body is empty."""
        with pytest.raises(BackendError) as exc_info:
            raise_for_response(400, body={}, default_message="Fallback message")
        assert "Fallback message" in str(exc_info.value)

    def test_uses_default_message_with_empty_string(self):
        """Test uses default_message when string body is empty."""
        with pytest.raises(BackendError) as exc_info:
            raise_for_response(400, body="   ", default_message="Empty body error")
        assert "Empty body error" in str(exc_info.value)
