"""Tests for org commands (delete-device, get-packets)."""
import base64
import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from hubblenetwork.org import Organization
from hubblenetwork.errors import BackendError
from hubblenetwork.cli import cli


class TestCloudDeleteDevice:
    def test_calls_cloud_request_with_delete_method(self):
        from hubblenetwork import cloud

        creds = MagicMock()
        creds.org_id = "org-123"
        env = MagicMock()

        with patch("hubblenetwork.cloud.cloud_request") as mock_req:
            cloud.delete_device(credentials=creds, env=env, device_id="dev-456")

        mock_req.assert_called_once_with(
            method="DELETE",
            path="/org/org-123/devices/dev-456",
            credentials=creds,
            env=env,
        )


class TestOrgDeleteDevice:
    def test_delete_device_calls_cloud(self):
        org = MagicMock(spec=Organization)
        org.credentials = MagicMock()
        org.env = MagicMock()

        with patch("hubblenetwork.org.cloud.delete_device") as mock_delete:
            Organization.delete_device(org, "dev-456")

        mock_delete.assert_called_once_with(
            credentials=org.credentials,
            env=org.env,
            device_id="dev-456",
        )

    def test_delete_device_propagates_error(self):
        org = MagicMock(spec=Organization)
        org.credentials = MagicMock()
        org.env = MagicMock()

        with patch(
            "hubblenetwork.org.cloud.delete_device",
            side_effect=BackendError("404: not found"),
        ):
            with pytest.raises(BackendError):
                Organization.delete_device(org, "dev-456")


class TestDeleteDeviceCLI:
    def test_confirm_yes_deletes_device(self):
        runner = CliRunner()
        device_id = "abc-123"

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org_cls.return_value = MagicMock(spec=Organization)
            mock_org = mock_org_cls.return_value
            result = runner.invoke(
                cli,
                ["org", "--org-id", "fake-org", "--token", "fake-token",
                 "delete-device", device_id],
                input="y\n",
            )

        assert result.exit_code == 0
        assert "deleted" in result.output
        assert "This cannot be undone" in result.output
        mock_org.delete_device.assert_called_once_with(device_id)

    def test_confirm_no_aborts(self):
        runner = CliRunner()
        device_id = "abc-123"

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org_cls.return_value = MagicMock(spec=Organization)
            mock_org = mock_org_cls.return_value
            result = runner.invoke(
                cli,
                ["org", "--org-id", "fake-org", "--token", "fake-token",
                 "delete-device", device_id],
                input="N\n",
            )

        assert result.exit_code != 0
        assert "Aborted" in result.output
        mock_org.delete_device.assert_not_called()

    def test_yes_flag_skips_prompt(self):
        runner = CliRunner()
        device_id = "abc-123"

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org_cls.return_value = MagicMock(spec=Organization)
            mock_org = mock_org_cls.return_value
            result = runner.invoke(
                cli,
                ["org", "--org-id", "fake-org", "--token", "fake-token",
                 "delete-device", device_id, "--yes"],
            )

        assert result.exit_code == 0
        assert "deleted" in result.output
        assert "This cannot be undone" not in result.output
        mock_org.delete_device.assert_called_once_with(device_id)

    def test_api_error_exits_nonzero(self):
        runner = CliRunner()
        device_id = "abc-123"

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org_cls.return_value = MagicMock(spec=Organization)
            mock_org = mock_org_cls.return_value
            mock_org.delete_device.side_effect = BackendError("404: not found")
            result = runner.invoke(
                cli,
                ["org", "--org-id", "fake-org", "--token", "fake-token",
                 "delete-device", device_id, "--yes"],
            )

        assert result.exit_code != 0
        assert result.exception is not None


class TestOrgRetrievePackets:
    """Tests for org.retrieve_packets — ensures payload is bytes, not a raw API string."""

    def _make_api_response(self, payload_bytes: bytes):
        """Return a minimal cloud API response dict with payload base64-encoded as the API does."""
        return {
            "packets": [
                {
                    "device": {
                        "timestamp": 1700000000,
                        "id": "dev-abc",
                        "name": "My Device",
                        "tags": {},
                        "payload": base64.b64encode(payload_bytes).decode("ascii"),
                        "rssi": -65,
                        "counter": 1,
                        "sequence_number": 0,
                    },
                    "location": {"latitude": 0.0, "longitude": 0.0},
                }
            ]
        }

    def test_payload_is_bytes(self):
        from hubblenetwork.org import Organization
        from hubblenetwork.packets import DecryptedPacket

        raw = b'\xde\xad\xbe\xef'
        api_resp = self._make_api_response(raw)

        org = MagicMock(spec=Organization)
        org.credentials = MagicMock()
        org.env = MagicMock()

        with patch("hubblenetwork.org.cloud.retrieve_packets", return_value=(api_resp, None)):
            packets = Organization.retrieve_packets(org, MagicMock())

        assert len(packets) == 1
        pkt = packets[0]
        assert isinstance(pkt, DecryptedPacket)
        assert isinstance(pkt.payload, bytes), "payload must be bytes, not a string"
        assert pkt.payload == raw

    def test_payload_format_hex_in_cli(self):
        """--payload-format hex must show hex output, not base64."""
        from hubblenetwork.cli import cli

        raw = b'\xab\xc6\x79'
        api_resp = {
            "packets": [
                {
                    "device": {
                        "timestamp": 1700000000,
                        "id": "dev-abc",
                        "name": "My Device",
                        "tags": {},
                        "payload": base64.b64encode(raw).decode("ascii"),
                        "rssi": -65,
                        "counter": 1,
                        "sequence_number": 0,
                    },
                    "location": {"latitude": 0.0, "longitude": 0.0},
                }
            ]
        }

        from hubblenetwork.packets import DecryptedPacket, Location

        runner = CliRunner()
        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org_cls.return_value = MagicMock(spec=Organization)
            mock_org = mock_org_cls.return_value
            mock_org.retrieve_packets.return_value = [
                DecryptedPacket(
                    timestamp=1700000000,
                    device_id="dev-abc",
                    device_name="My Device",
                    location=Location(lat=0.0, lon=0.0, fake=True),
                    tags={},
                    payload=raw,
                    rssi=-65,
                    counter=1,
                    sequence=0,
                )
            ]
            result = runner.invoke(
                cli,
                ["org", "--org-id", "fake-org", "--token", "fake-token",
                 "get-packets", "dev-abc", "--payload-format", "hex"],
            )

        assert result.exit_code == 0, result.output
        assert "ABC679" in result.output
        assert base64.b64encode(raw).decode("ascii") not in result.output
