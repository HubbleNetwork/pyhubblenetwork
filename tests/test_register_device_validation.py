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


class TestPeriodSecondsValidation:
    def test_period_seconds_requires_aes_128_eax(self, org):
        with pytest.raises(ValidationError, match="AES-128-EAX"):
            org.register_device(
                encryption="AES-256-CTR",
                counter_source="DEVICE_UPTIME",
                period_seconds=1024,
            )

    def test_period_seconds_requires_device_uptime(self, org):
        with pytest.raises(ValidationError, match="DEVICE_UPTIME"):
            org.register_device(
                encryption="AES-128-EAX",
                counter_source="UNIX_TIME",
                period_seconds=1024,
            )


class TestPeriodExponentValidation:
    def test_period_exponent_requires_aes_128_eax(self, org):
        with pytest.raises(ValidationError, match="AES-128-EAX"):
            org.register_device(
                encryption="AES-256-CTR",
                counter_source="DEVICE_UPTIME",
                period_exponent=15,
            )

    def test_period_exponent_requires_device_uptime(self, org):
        with pytest.raises(ValidationError, match="DEVICE_UPTIME"):
            org.register_device(
                encryption="AES-128-EAX",
                counter_source="UNIX_TIME",
                period_exponent=15,
            )


class TestMutualExclusion:
    def test_period_seconds_and_exponent_both_set_rejected(self, org):
        with pytest.raises(ValidationError, match="at most one of period_seconds, period_exponent"):
            org.register_device(
                encryption="AES-128-EAX",
                counter_source="DEVICE_UPTIME",
                period_seconds=1024,
                period_exponent=10,
            )


class TestForwardingToCloud:
    @patch("hubblenetwork.org.cloud.register_device")
    def test_period_seconds_forwarded_as_period_in_seconds(self, mock_reg, org):
        mock_reg.return_value = {"devices": [{"device_id": "d1", "key": "YWJj"}]}
        org.register_device(
            encryption="AES-128-EAX",
            counter_source="DEVICE_UPTIME",
            period_seconds=1024,
        )
        kwargs = mock_reg.call_args.kwargs
        assert kwargs["period_in_seconds"] == 1024
        assert kwargs["period_exponent"] is None

    @patch("hubblenetwork.org.cloud.register_device")
    def test_period_exponent_forwarded_unchanged(self, mock_reg, org):
        mock_reg.return_value = {"devices": [{"device_id": "d1", "key": "YWJj"}]}
        org.register_device(
            encryption="AES-128-EAX",
            counter_source="DEVICE_UPTIME",
            period_exponent=15,
        )
        kwargs = mock_reg.call_args.kwargs
        assert kwargs["period_exponent"] == 15
        assert kwargs["period_in_seconds"] is None
