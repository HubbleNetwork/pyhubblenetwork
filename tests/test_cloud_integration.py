"""Integration tests for cloud.py against real Hubble API."""

import os
import time
import pytest
from hubblenetwork import Organization
from hubblenetwork.cloud import (
    Environment,
    Credentials,
    get_env_from_credentials,
    list_devices,
    register_device,
    update_device,
    retrieve_packets,
    retrieve_org_metadata,
)
from hubblenetwork.errors import ValidationError

pytestmark = pytest.mark.integration


class TestProdEnvironment:
    """Integration tests against PROD (api.hubble.com)."""

    @pytest.fixture
    def credentials(self):
        org_id = os.environ.get("HUBBLE_PROD_ORG_ID")
        api_token = os.environ.get("HUBBLE_PROD_API_TOKEN")
        if not org_id or not api_token:
            pytest.skip("HUBBLE_PROD_ORG_ID and HUBBLE_PROD_API_TOKEN required")
        return Credentials(org_id=org_id, api_token=api_token)

    @pytest.fixture
    def env(self, credentials):
        environment = get_env_from_credentials(credentials)
        assert environment is not None
        assert environment.name == "PROD"
        return environment

    def test_get_env_from_credentials(self, credentials):
        env = get_env_from_credentials(credentials)
        assert env is not None
        assert env.name == "PROD"
        assert env.url == "https://api.hubble.com"

    def test_retrieve_org_metadata(self, credentials, env):
        metadata = retrieve_org_metadata(credentials=credentials, env=env)
        assert metadata is not None
        assert "name" in metadata or "id" in metadata

    def test_list_devices(self, credentials, env):
        result, continuation_token = list_devices(credentials=credentials, env=env)
        assert "devices" in result
        assert isinstance(result["devices"], list)

    def test_register_and_update_device(self, credentials, env):
        # Register a new device
        result = register_device(credentials=credentials, env=env)
        assert "devices" in result
        assert len(result["devices"]) > 0
        device = result["devices"][0]
        device_id = device["device_id"]

        # Update the device name
        test_name = f"test-device-{int(time.time())}"
        updated = update_device(
            credentials=credentials,
            env=env,
            device_id=device_id,
            name=test_name,
        )
        assert updated is not None

    def test_register_device_with_unix_time(self, credentials, env):
        result = register_device(
            credentials=credentials, env=env, counter_source="UNIX_TIME"
        )
        assert "devices" in result
        assert len(result["devices"]) > 0
        assert result["devices"][0]["device_id"]

    def test_register_device_with_device_uptime(self, credentials, env):
        result = register_device(
            credentials=credentials, env=env, counter_source="DEVICE_UPTIME"
        )
        assert "devices" in result
        assert len(result["devices"]) > 0
        assert result["devices"][0]["device_id"]

    def test_register_device_aes_128_eax(self, credentials, env):
        result = register_device(
            credentials=credentials,
            env=env,
            encryption="AES-128-EAX",
            counter_source="DEVICE_UPTIME",
            period_in_seconds=1024,
        )
        assert "devices" in result
        assert len(result["devices"]) > 0
        assert result["devices"][0]["device_id"]

    def test_retrieve_packets(self, credentials, env):
        # First get a device to query
        devices_result, _ = list_devices(credentials=credentials, env=env)
        if not devices_result["devices"]:
            pytest.skip("No devices available to query packets")

        device_id = devices_result["devices"][0]["id"]
        result, _ = retrieve_packets(
            credentials=credentials,
            env=env,
            device_id=device_id,
            days=7,
        )
        assert "packets" in result


class TestTestingEnvironment:
    """Integration tests against TESTING (api-testing.hubblenetwork.io)."""

    @pytest.fixture
    def credentials(self):
        org_id = os.environ.get("HUBBLE_TESTING_ORG_ID")
        api_token = os.environ.get("HUBBLE_TESTING_API_TOKEN")
        if not org_id or not api_token:
            pytest.skip("HUBBLE_TESTING_ORG_ID and HUBBLE_TESTING_API_TOKEN required")
        return Credentials(org_id=org_id, api_token=api_token)

    @pytest.fixture
    def env(self, credentials):
        environment = get_env_from_credentials(credentials)
        assert environment is not None
        assert environment.name == "TESTING"
        return environment

    def test_get_env_from_credentials(self, credentials):
        env = get_env_from_credentials(credentials)
        assert env is not None
        assert env.name == "TESTING"
        assert env.url == "https://api-testing.hubblenetwork.io"

    def test_retrieve_org_metadata(self, credentials, env):
        metadata = retrieve_org_metadata(credentials=credentials, env=env)
        assert metadata is not None

    def test_list_devices(self, credentials, env):
        result, _ = list_devices(credentials=credentials, env=env)
        assert "devices" in result

    def test_register_and_update_device(self, credentials, env):
        result = register_device(credentials=credentials, env=env)
        assert "devices" in result
        device_id = result["devices"][0]["device_id"]

        test_name = f"test-device-{int(time.time())}"
        updated = update_device(
            credentials=credentials,
            env=env,
            device_id=device_id,
            name=test_name,
        )
        assert updated is not None

    def test_register_device_with_unix_time(self, credentials, env):
        result = register_device(
            credentials=credentials, env=env, counter_source="UNIX_TIME"
        )
        assert "devices" in result
        assert len(result["devices"]) > 0
        assert result["devices"][0]["device_id"]

    def test_register_device_with_device_uptime(self, credentials, env):
        result = register_device(
            credentials=credentials, env=env, counter_source="DEVICE_UPTIME"
        )
        assert "devices" in result
        assert len(result["devices"]) > 0
        assert result["devices"][0]["device_id"]

    def test_register_device_aes_128_eax(self, credentials, env):
        result = register_device(
            credentials=credentials,
            env=env,
            encryption="AES-128-EAX",
            counter_source="DEVICE_UPTIME",
            period_in_seconds=1024,
        )
        assert "devices" in result
        assert len(result["devices"]) > 0
        assert result["devices"][0]["device_id"]


class TestInvalidCredentials:
    """Test behavior with invalid credentials."""

    def test_invalid_credentials_returns_none(self):
        bad_creds = Credentials(org_id="invalid-org", api_token="invalid-token")
        env = get_env_from_credentials(bad_creds)
        assert env is None


class TestEidRotationValidation:
    """SDK-side validation of EID rotation parameters in Organization.register_device().

    These tests fire ValidationError before any cloud call beyond Organization.__init__,
    so they only need credentials to construct the Organization instance.
    Uses TESTING credentials preferentially, falling back to PROD.
    """

    @pytest.fixture
    def org(self):
        org_id = os.environ.get("HUBBLE_TESTING_ORG_ID") or os.environ.get("HUBBLE_PROD_ORG_ID")
        api_token = os.environ.get("HUBBLE_TESTING_API_TOKEN") or os.environ.get("HUBBLE_PROD_API_TOKEN")
        if not org_id or not api_token:
            pytest.skip("No credentials available (set HUBBLE_TESTING_* or HUBBLE_PROD_*)")
        return Organization(org_id=org_id, api_token=api_token)

    def test_invalid_counter_source_raises(self, org):
        with pytest.raises(ValidationError, match="counter_source"):
            org.register_device(counter_source="INVALID_SOURCE")
