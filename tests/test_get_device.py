"""Unit tests for single-device GET (cloud + org layers)."""
from unittest.mock import MagicMock, patch

import pytest

from hubblenetwork import cloud
from hubblenetwork.cloud import Credentials, Environment
from hubblenetwork.errors import NotFoundError
from hubblenetwork.org import Organization


@pytest.fixture
def env():
    return Environment(name="TESTING", url="https://test.example.com")


@pytest.fixture
def credentials():
    return Credentials(org_id="test-org", api_token="test-token")


@pytest.fixture
def org():
    with patch("hubblenetwork.org.cloud.get_env_from_credentials") as mock_env, \
         patch("hubblenetwork.org.cloud.retrieve_org_metadata") as mock_meta:
        mock_env.return_value = MagicMock(name="TESTING", url="https://test.example.com")
        mock_meta.return_value = {"name": "Test Org"}
        return Organization(org_id="test-org", api_token="test-token")


class TestCloudGetDevice:
    @patch("hubblenetwork.cloud.cloud_request")
    def test_returns_unwrapped_json(self, mock_request, credentials, env):
        mock_request.return_value = ({"id": "d1", "name": "n"}, None)
        result = cloud.get_device(credentials=credentials, env=env, device_id="d1")
        assert result == {"id": "d1", "name": "n"}

    @patch("hubblenetwork.cloud.cloud_request")
    def test_hits_single_device_path(self, mock_request, credentials, env):
        mock_request.return_value = ({"id": "d1"}, None)
        cloud.get_device(credentials=credentials, env=env, device_id="d1")
        kwargs = mock_request.call_args.kwargs
        assert kwargs["method"] == "GET"
        assert kwargs["path"] == "/org/test-org/devices/d1"


class TestOrgGetDevice:
    @patch("hubblenetwork.org.cloud.get_device")
    def test_returns_device_on_success(self, mock_get, org):
        mock_get.return_value = {"id": "d1", "name": "n", "tags": {}}
        device = org.get_device("d1")
        assert device.id == "d1"

    @patch("hubblenetwork.org.cloud.get_device", side_effect=NotFoundError("404: nope"))
    def test_returns_none_when_not_found(self, mock_get, org):
        assert org.get_device("missing") is None
