"""Tests for org.py Organization class."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from hubblenetwork.org import Organization
from hubblenetwork.device import Device
from hubblenetwork.cloud import Credentials, Environment
from hubblenetwork.packets import DecryptedPacket, EncryptedPacket, Location
from hubblenetwork.errors import InvalidCredentialsError


class TestOrganizationInit:
    """Tests for Organization constructor."""

    def test_init_with_credentials_object(self):
        """Test initialization with Credentials object."""
        mock_env = Environment(name="TEST", url="https://api.test.com")

        with patch("hubblenetwork.org.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = mock_env
            with patch("hubblenetwork.org.cloud.retrieve_org_metadata") as mock_meta:
                mock_meta.return_value = {"name": "Test Org"}

                creds = Credentials(org_id="org-123", api_token="token-abc")
                org = Organization(credentials=creds)

                assert org.credentials == creds
                assert org.env == mock_env
                assert org.name == "Test Org"

    def test_init_with_explicit_org_id_and_token(self):
        """Test initialization with explicit org_id and api_token."""
        mock_env = Environment(name="TEST", url="https://api.test.com")

        with patch("hubblenetwork.org.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = mock_env
            with patch("hubblenetwork.org.cloud.retrieve_org_metadata") as mock_meta:
                mock_meta.return_value = {"name": "My Org"}

                org = Organization(org_id="my-org", api_token="my-token")

                assert org.credentials.org_id == "my-org"
                assert org.credentials.api_token == "my-token"
                assert org.name == "My Org"

    def test_init_raises_invalid_credentials_error(self):
        """Test initialization raises InvalidCredentialsError when env is None."""
        with patch("hubblenetwork.org.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = None

            with pytest.raises(InvalidCredentialsError):
                Organization(org_id="bad-org", api_token="bad-token")

    def test_org_id_property(self):
        """Test org_id property returns credentials.org_id."""
        mock_env = Environment(name="TEST", url="https://api.test.com")

        with patch("hubblenetwork.org.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = mock_env
            with patch("hubblenetwork.org.cloud.retrieve_org_metadata") as mock_meta:
                mock_meta.return_value = {"name": "Test Org"}

                org = Organization(org_id="test-org-id", api_token="token")

                assert org.org_id == "test-org-id"


class TestOrganizationRegisterDevice:
    """Tests for Organization.register_device method."""

    def _create_org(self):
        """Helper to create an Organization with mocked dependencies."""
        mock_env = Environment(name="TEST", url="https://api.test.com")

        with patch("hubblenetwork.org.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = mock_env
            with patch("hubblenetwork.org.cloud.retrieve_org_metadata") as mock_meta:
                mock_meta.return_value = {"name": "Test Org"}
                return Organization(org_id="org-123", api_token="token")

    def test_register_device_success(self):
        """Test successful device registration."""
        org = self._create_org()

        with patch("hubblenetwork.org.cloud.register_device") as mock_register:
            import base64

            test_key = b"\x00" * 32
            mock_register.return_value = {
                "devices": [
                    {"device_id": "new-device-123", "key": base64.b64encode(test_key).decode()}
                ]
            }

            device = org.register_device()

            assert isinstance(device, Device)
            assert device.id == "new-device-123"
            assert device.key == test_key

    def test_register_device_with_encryption(self):
        """Test device registration with custom encryption."""
        org = self._create_org()

        with patch("hubblenetwork.org.cloud.register_device") as mock_register:
            mock_register.return_value = {
                "devices": [{"device_id": "dev-1", "key": None}]
            }

            org.register_device(encryption="AES-128-CTR")

            mock_register.assert_called_once()
            call_kwargs = mock_register.call_args.kwargs
            assert call_kwargs.get("encryption") == "AES-128-CTR"


class TestOrganizationSetDeviceName:
    """Tests for Organization.set_device_name method."""

    def _create_org(self):
        mock_env = Environment(name="TEST", url="https://api.test.com")
        with patch("hubblenetwork.org.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = mock_env
            with patch("hubblenetwork.org.cloud.retrieve_org_metadata") as mock_meta:
                mock_meta.return_value = {"name": "Test Org"}
                return Organization(org_id="org-123", api_token="token")

    def test_set_device_name_success(self):
        """Test successful device name update."""
        org = self._create_org()

        with patch("hubblenetwork.org.cloud.update_device") as mock_update:
            mock_update.return_value = {"id": "dev-123", "name": "New Name"}

            device = org.set_device_name("dev-123", "New Name")

            assert isinstance(device, Device)
            assert device.id == "dev-123"
            assert device.name == "New Name"


class TestOrganizationListDevices:
    """Tests for Organization.list_devices method."""

    def _create_org(self):
        mock_env = Environment(name="TEST", url="https://api.test.com")
        with patch("hubblenetwork.org.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = mock_env
            with patch("hubblenetwork.org.cloud.retrieve_org_metadata") as mock_meta:
                mock_meta.return_value = {"name": "Test Org"}
                return Organization(org_id="org-123", api_token="token")

    def test_list_devices_success(self):
        """Test successful device listing."""
        org = self._create_org()

        with patch("hubblenetwork.org.cloud.list_devices") as mock_list:
            mock_list.return_value = (
                {
                    "devices": [
                        {"id": "dev-1", "name": "Device 1", "active": True},
                        {"id": "dev-2", "name": "Device 2", "active": False},
                    ]
                },
                None,  # No continuation token
            )

            devices = org.list_devices()

            assert len(devices) == 2
            assert all(isinstance(d, Device) for d in devices)
            assert devices[0].id == "dev-1"
            assert devices[1].id == "dev-2"

    def test_list_devices_with_pagination(self):
        """Test device listing with pagination."""
        org = self._create_org()

        with patch("hubblenetwork.org.cloud.list_devices") as mock_list:
            mock_list.side_effect = [
                ({"devices": [{"id": "dev-1"}]}, "token-page-2"),
                ({"devices": [{"id": "dev-2"}]}, None),
            ]

            devices = org.list_devices()

            assert len(devices) == 2
            assert mock_list.call_count == 2

    def test_list_devices_empty(self):
        """Test device listing with no devices."""
        org = self._create_org()

        with patch("hubblenetwork.org.cloud.list_devices") as mock_list:
            mock_list.return_value = ({"devices": []}, None)

            devices = org.list_devices()

            assert devices == []


class TestOrganizationRetrievePackets:
    """Tests for Organization.retrieve_packets method."""

    def _create_org(self):
        mock_env = Environment(name="TEST", url="https://api.test.com")
        with patch("hubblenetwork.org.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = mock_env
            with patch("hubblenetwork.org.cloud.retrieve_org_metadata") as mock_meta:
                mock_meta.return_value = {"name": "Test Org"}
                return Organization(org_id="org-123", api_token="token")

    def test_retrieve_packets_success(self):
        """Test successful packet retrieval."""
        org = self._create_org()
        device = Device(id="dev-123")

        with patch("hubblenetwork.org.cloud.retrieve_packets") as mock_retrieve:
            mock_retrieve.return_value = (
                {
                    "packets": [
                        {
                            "device": {
                                "id": "dev-123",
                                "name": "Test Device",
                                "timestamp": 1700000000,
                                "tags": {"env": "test"},
                                "payload": b"Hello",
                                "rssi": -65,
                                "counter": 20000,
                                "sequence_number": 42,
                            },
                            "location": {"latitude": 37.7749, "longitude": -122.4194},
                        }
                    ]
                },
                None,
            )

            packets = org.retrieve_packets(device)

            assert len(packets) == 1
            assert isinstance(packets[0], DecryptedPacket)
            assert packets[0].device_id == "dev-123"
            assert packets[0].timestamp == 1700000000

    def test_retrieve_packets_with_pagination(self):
        """Test packet retrieval with pagination."""
        org = self._create_org()
        device = Device(id="dev-123")

        with patch("hubblenetwork.org.cloud.retrieve_packets") as mock_retrieve:
            mock_retrieve.side_effect = [
                (
                    {
                        "packets": [
                            {
                                "device": {
                                    "id": "dev-123",
                                    "timestamp": 1700000000,
                                    "tags": {},
                                    "payload": b"P1",
                                    "rssi": -65,
                                    "counter": 1,
                                    "sequence_number": 1,
                                },
                                "location": {"latitude": 0, "longitude": 0},
                            }
                        ]
                    },
                    "next-page",
                ),
                (
                    {
                        "packets": [
                            {
                                "device": {
                                    "id": "dev-123",
                                    "timestamp": 1700000001,
                                    "tags": {},
                                    "payload": b"P2",
                                    "rssi": -70,
                                    "counter": 2,
                                    "sequence_number": 2,
                                },
                                "location": {"latitude": 0, "longitude": 0},
                            }
                        ]
                    },
                    None,
                ),
            ]

            packets = org.retrieve_packets(device)

            assert len(packets) == 2
            assert mock_retrieve.call_count == 2

    def test_retrieve_packets_with_custom_days(self):
        """Test packet retrieval with custom days parameter."""
        org = self._create_org()
        device = Device(id="dev-123")

        with patch("hubblenetwork.org.cloud.retrieve_packets") as mock_retrieve:
            mock_retrieve.return_value = ({"packets": []}, None)

            org.retrieve_packets(device, days=30)

            call_kwargs = mock_retrieve.call_args.kwargs
            assert call_kwargs.get("days") == 30


class TestOrganizationIngestPacket:
    """Tests for Organization.ingest_packet method."""

    def _create_org(self):
        mock_env = Environment(name="TEST", url="https://api.test.com")
        with patch("hubblenetwork.org.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = mock_env
            with patch("hubblenetwork.org.cloud.retrieve_org_metadata") as mock_meta:
                mock_meta.return_value = {"name": "Test Org"}
                return Organization(org_id="org-123", api_token="token")

    def test_ingest_packet_success(self):
        """Test successful packet ingestion."""
        org = self._create_org()
        packet = EncryptedPacket(
            timestamp=1700000000,
            location=Location(lat=37.7749, lon=-122.4194),
            payload=b"\x00\x01\x02\x03",
            rssi=-70,
        )

        with patch("hubblenetwork.org.cloud.ingest_packet") as mock_ingest:
            mock_ingest.return_value = {"status": "ok"}

            org.ingest_packet(packet)

            mock_ingest.assert_called_once()
            call_kwargs = mock_ingest.call_args.kwargs
            assert call_kwargs.get("packet") == packet
