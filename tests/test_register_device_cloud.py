import pytest
from unittest.mock import patch, MagicMock
from hubblenetwork.cloud import register_device, Credentials, Environment


@pytest.fixture
def env():
    return Environment(name="TESTING", url="https://test.example.com")


@pytest.fixture
def credentials():
    return Credentials(org_id="test-org", api_token="test-token")


class TestRegisterDeviceRequestBody:
    @patch("hubblenetwork.cloud.cloud_request")
    def test_default_body(self, mock_request, credentials, env):
        mock_request.return_value = ({"devices": [{"device_id": "d1", "key": "abc="}]}, None)
        register_device(credentials=credentials, env=env)
        body = mock_request.call_args.kwargs["json"]
        assert body == {"n_devices": 1, "encryption": "AES-256-CTR"}

    @patch("hubblenetwork.cloud.cloud_request")
    def test_counter_source_no_pool_size(self, mock_request, credentials, env):
        """pool_size should NOT be included in the request body."""
        mock_request.return_value = ({"devices": [{"device_id": "d1", "key": "abc="}]}, None)
        register_device(credentials=credentials, env=env, counter_source="DEVICE_UPTIME")
        body = mock_request.call_args.kwargs["json"]
        assert body == {
            "n_devices": 1,
            "encryption": "AES-256-CTR",
            "eid_rotation": {"counter_source": "DEVICE_UPTIME"},
        }

    @patch("hubblenetwork.cloud.cloud_request")
    def test_aes_eax_with_period_seconds(self, mock_request, credentials, env):
        mock_request.return_value = ({"devices": [{"device_id": "d1", "key": "abc="}]}, None)
        register_device(
            credentials=credentials,
            env=env,
            encryption="AES-128-EAX",
            counter_source="DEVICE_UPTIME",
            period_in_seconds=1024,
        )
        body = mock_request.call_args.kwargs["json"]
        assert body == {
            "n_devices": 1,
            "encryption": "AES-128-EAX",
            "eid_rotation": {
                "counter_source": "DEVICE_UPTIME",
                "period_in_seconds": 1024,
            },
        }

    @patch("hubblenetwork.cloud.cloud_request")
    def test_counter_source_without_period(self, mock_request, credentials, env):
        """period_in_seconds omitted when not provided."""
        mock_request.return_value = ({"devices": [{"device_id": "d1", "key": "abc="}]}, None)
        register_device(
            credentials=credentials,
            env=env,
            encryption="AES-128-EAX",
            counter_source="DEVICE_UPTIME",
        )
        body = mock_request.call_args.kwargs["json"]
        assert body == {
            "n_devices": 1,
            "encryption": "AES-128-EAX",
            "eid_rotation": {"counter_source": "DEVICE_UPTIME"},
        }

    @patch("hubblenetwork.cloud.cloud_request")
    def test_aes_eax_with_period_exponent(self, mock_request, credentials, env):
        mock_request.return_value = ({"devices": [{"device_id": "d1", "key": "abc="}]}, None)
        register_device(
            credentials=credentials,
            env=env,
            encryption="AES-128-EAX",
            counter_source="DEVICE_UPTIME",
            period_exponent=15,
        )
        body = mock_request.call_args.kwargs["json"]
        assert body == {
            "n_devices": 1,
            "encryption": "AES-128-EAX",
            "eid_rotation": {
                "counter_source": "DEVICE_UPTIME",
                "period_exponent": 15,
            },
        }
