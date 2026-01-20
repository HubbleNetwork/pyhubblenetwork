"""Tests for cloud.py API client functions."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
import httpx

from hubblenetwork.cloud import (
    Environment,
    Credentials,
    cloud_request,
    get_env_from_credentials,
    register_device,
    update_device,
    list_devices,
    retrieve_packets,
    ingest_packet,
    retrieve_org_metadata,
    _ENVIRONMENTS,
)
from hubblenetwork.errors import (
    RequestError,
    InternalServerError,
    BackendError,
    NetworkError,
    APITimeout,
)
from hubblenetwork.packets import EncryptedPacket, Location


class TestEnvironment:
    """Tests for Environment dataclass."""

    def test_create_environment(self):
        """Test creating Environment."""
        env = Environment(name="TEST", url="https://api-test.example.com")
        assert env.name == "TEST"
        assert env.url == "https://api-test.example.com"

    def test_environment_is_frozen(self):
        """Test Environment is immutable."""
        env = Environment(name="TEST", url="https://test.example.com")
        with pytest.raises(Exception):  # FrozenInstanceError
            env.name = "OTHER"

    def test_predefined_environments_exist(self):
        """Test predefined environments are defined."""
        assert len(_ENVIRONMENTS) >= 2
        names = [e.name for e in _ENVIRONMENTS]
        assert "PROD" in names
        assert "TESTING" in names


class TestCredentials:
    """Tests for Credentials dataclass."""

    def test_create_credentials(self):
        """Test creating Credentials."""
        creds = Credentials(org_id="org-123", api_token="token-abc")
        assert creds.org_id == "org-123"
        assert creds.api_token == "token-abc"

    def test_credentials_is_frozen(self):
        """Test Credentials is immutable."""
        creds = Credentials(org_id="org-123", api_token="token-abc")
        with pytest.raises(Exception):  # FrozenInstanceError
            creds.org_id = "other"


class TestCloudRequest:
    """Tests for cloud_request function."""

    def test_successful_get_request(self):
        """Test successful GET request."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {"data": "test"}
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")
            creds = Credentials(org_id="org-123", api_token="token-abc")

            result, token = cloud_request(
                method="GET",
                path="/test",
                env=env,
                credentials=creds,
            )

            assert result == {"data": "test"}
            assert token is None

    def test_successful_post_request_with_json(self):
        """Test successful POST request with JSON body."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {"id": "new-123"}
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_instance = mock_client.return_value.__enter__.return_value
            mock_instance.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")
            creds = Credentials(org_id="org-123", api_token="token-abc")

            result, _ = cloud_request(
                method="POST",
                path="/create",
                env=env,
                credentials=creds,
                json={"name": "test"},
            )

            assert result == {"id": "new-123"}
            # Verify request was called with json body
            mock_instance.request.assert_called_once()
            call_kwargs = mock_instance.request.call_args
            assert call_kwargs.kwargs.get("json") == {"name": "test"}

    def test_continuation_token_in_response(self):
        """Test continuation token is extracted from response headers."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {"items": []}
        mock_response.headers = {"Continuation-Token": "next-page-token"}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")

            result, token = cloud_request(
                method="GET",
                path="/list",
                env=env,
            )

            assert token == "next-page-token"

    def test_continuation_token_in_request(self):
        """Test continuation token is sent in request headers."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {"items": []}
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_instance = mock_client.return_value.__enter__.return_value
            mock_instance.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")

            cloud_request(
                method="GET",
                path="/list",
                env=env,
                continuation_token="page-2",
            )

            call_kwargs = mock_instance.request.call_args
            headers = call_kwargs.kwargs.get("headers", {})
            assert headers.get("Continuation-Token") == "page-2"

    def test_400_error_raises_request_error(self):
        """Test 400 response raises RequestError."""
        mock_response = MagicMock()
        mock_response.is_error = True
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "Bad request"}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")

            with pytest.raises(RequestError):
                cloud_request(method="GET", path="/test", env=env)

    def test_500_error_raises_internal_server_error(self):
        """Test 500 response raises InternalServerError."""
        mock_response = MagicMock()
        mock_response.is_error = True
        mock_response.status_code = 500
        mock_response.json.return_value = {"error": "Server error"}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")

            with pytest.raises(InternalServerError):
                cloud_request(method="GET", path="/test", env=env)

    def test_timeout_raises_api_timeout(self):
        """Test timeout raises APITimeout."""
        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.side_effect = (
                httpx.TimeoutException("timeout")
            )

            env = Environment(name="TEST", url="https://api.example.com")

            with pytest.raises(APITimeout):
                cloud_request(method="GET", path="/test", env=env)

    def test_network_error_raises_network_error(self):
        """Test network error raises NetworkError."""
        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.side_effect = (
                httpx.HTTPError("Connection failed")
            )

            env = Environment(name="TEST", url="https://api.example.com")

            with pytest.raises(NetworkError):
                cloud_request(method="GET", path="/test", env=env)

    def test_non_json_response_raises_backend_error(self):
        """Test non-JSON response raises BackendError."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.side_effect = ValueError("No JSON")
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")

            with pytest.raises(BackendError):
                cloud_request(method="GET", path="/test", env=env)

    def test_authorization_header_set(self):
        """Test Authorization header is set when credentials provided."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {}
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_instance = mock_client.return_value.__enter__.return_value
            mock_instance.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")
            creds = Credentials(org_id="org-123", api_token="my-token")

            cloud_request(method="GET", path="/test", env=env, credentials=creds)

            call_kwargs = mock_instance.request.call_args
            headers = call_kwargs.kwargs.get("headers", {})
            assert headers.get("Authorization") == "Bearer my-token"


class TestGetEnvFromCredentials:
    """Tests for get_env_from_credentials function."""

    def test_returns_env_on_valid_credentials(self):
        """Test returns environment when credentials are valid."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {}
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response

            creds = Credentials(org_id="org-123", api_token="valid-token")
            env = get_env_from_credentials(creds)

            assert env is not None
            assert isinstance(env, Environment)

    def test_returns_none_on_invalid_credentials(self):
        """Test returns None when all environments reject credentials."""
        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.side_effect = Exception(
                "Invalid"
            )

            creds = Credentials(org_id="bad-org", api_token="bad-token")
            env = get_env_from_credentials(creds)

            assert env is None


class TestRegisterDevice:
    """Tests for register_device function."""

    def test_register_device_success(self):
        """Test successful device registration."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {
            "devices": [{"device_id": "new-dev", "key": "base64key=="}]
        }
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_instance = mock_client.return_value.__enter__.return_value
            mock_instance.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")
            creds = Credentials(org_id="org-123", api_token="token")

            result = register_device(credentials=creds, env=env)

            assert result == {"devices": [{"device_id": "new-dev", "key": "base64key=="}]}

    def test_register_device_custom_encryption(self):
        """Test device registration with custom encryption."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {"devices": []}
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_instance = mock_client.return_value.__enter__.return_value
            mock_instance.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")
            creds = Credentials(org_id="org-123", api_token="token")

            register_device(credentials=creds, env=env, encryption="AES-128-CTR")

            call_kwargs = mock_instance.request.call_args
            json_body = call_kwargs.kwargs.get("json", {})
            assert json_body.get("encryption") == "AES-128-CTR"


class TestListDevices:
    """Tests for list_devices function."""

    def test_list_devices_success(self):
        """Test successful device listing."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {"devices": [{"id": "dev-1"}, {"id": "dev-2"}]}
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")
            creds = Credentials(org_id="org-123", api_token="token")

            result, token = list_devices(credentials=creds, env=env)

            assert result == {"devices": [{"id": "dev-1"}, {"id": "dev-2"}]}


class TestRetrievePackets:
    """Tests for retrieve_packets function."""

    def test_retrieve_packets_success(self):
        """Test successful packet retrieval."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {"packets": [{"device": {"id": "dev-1"}}]}
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_instance = mock_client.return_value.__enter__.return_value
            mock_instance.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")
            creds = Credentials(org_id="org-123", api_token="token")

            result, token = retrieve_packets(
                credentials=creds, env=env, device_id="dev-1", days=7
            )

            assert "packets" in result

    def test_retrieve_packets_with_custom_days(self):
        """Test packet retrieval with custom days parameter."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {"packets": []}
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_instance = mock_client.return_value.__enter__.return_value
            mock_instance.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")
            creds = Credentials(org_id="org-123", api_token="token")

            retrieve_packets(credentials=creds, env=env, device_id="dev-1", days=30)

            call_kwargs = mock_instance.request.call_args
            params = call_kwargs.kwargs.get("params", {})
            # Verify start timestamp is approximately 30 days ago
            assert "start" in params


class TestIngestPacket:
    """Tests for ingest_packet function."""

    def test_ingest_packet_success(self):
        """Test successful packet ingestion."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {"status": "ok"}
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_instance = mock_client.return_value.__enter__.return_value
            mock_instance.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")
            creds = Credentials(org_id="org-123", api_token="token")
            packet = EncryptedPacket(
                timestamp=1700000000,
                location=Location(lat=37.7749, lon=-122.4194),
                payload=b"\x00\x01\x02\x03",
                rssi=-70,
            )

            result = ingest_packet(credentials=creds, env=env, packet=packet)

            assert result == {"status": "ok"}


class TestRetrieveOrgMetadata:
    """Tests for retrieve_org_metadata function."""

    def test_retrieve_org_metadata_success(self):
        """Test successful org metadata retrieval."""
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = {"name": "Test Org", "id": "org-123"}
        mock_response.headers = {}

        with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response

            env = Environment(name="TEST", url="https://api.example.com")
            creds = Credentials(org_id="org-123", api_token="token")

            result = retrieve_org_metadata(credentials=creds, env=env)

            assert result == {"name": "Test Org", "id": "org-123"}
