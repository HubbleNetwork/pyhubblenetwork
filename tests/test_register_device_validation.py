import pytest
from unittest.mock import patch, MagicMock
from hubblenetwork.org import Organization
from hubblenetwork.errors import ValidationError


@pytest.fixture
def org():
    """Create an Organization with mocked cloud calls."""
    with patch("hubblenetwork.org.cloud.get_env_from_credentials") as mock_env, \
         patch("hubblenetwork.org.cloud.retrieve_org_metadata") as mock_meta:
        mock_env.return_value = MagicMock(name="TESTING", url="https://test.example.com")
        mock_meta.return_value = {"name": "Test Org"}
        return Organization(org_id="test-org", api_token="test-token")


class TestPeriodInSecondsValidation:
    def test_period_requires_aes_128_eax(self, org):
        with pytest.raises(ValidationError, match="AES-128-EAX"):
            org.register_device(
                encryption="AES-256-CTR",
                counter_source="DEVICE_UPTIME",
                period_in_seconds=1024,
            )

    def test_period_requires_device_uptime(self, org):
        with pytest.raises(ValidationError, match="DEVICE_UPTIME"):
            org.register_device(
                encryption="AES-128-EAX",
                counter_source="UNIX_TIME",
                period_in_seconds=1024,
            )

    def test_period_must_be_power_of_two(self, org):
        with pytest.raises(ValidationError, match="power of 2"):
            org.register_device(
                encryption="AES-128-EAX",
                counter_source="DEVICE_UPTIME",
                period_in_seconds=1000,
            )

    def test_period_must_be_in_range(self, org):
        with pytest.raises(ValidationError, match="power of 2"):
            org.register_device(
                encryption="AES-128-EAX",
                counter_source="DEVICE_UPTIME",
                period_in_seconds=65536,
            )

    def test_period_zero_is_invalid(self, org):
        with pytest.raises(ValidationError, match="power of 2"):
            org.register_device(
                encryption="AES-128-EAX",
                counter_source="DEVICE_UPTIME",
                period_in_seconds=0,
            )

    def test_period_negative_is_invalid(self, org):
        with pytest.raises(ValidationError, match="power of 2"):
            org.register_device(
                encryption="AES-128-EAX",
                counter_source="DEVICE_UPTIME",
                period_in_seconds=-1,
            )
