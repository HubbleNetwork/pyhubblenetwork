from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from hubblenetwork.cli import cli
from hubblenetwork.device import Device

ORG = "11111111-2222-3333-4444-555555555555"


def _run(args):
    org = MagicMock()
    org.register_device.return_value = Device(id="d1", key=b"abc", claim_id="d1")
    with patch("hubblenetwork.cli.Organization", return_value=org):
        result = CliRunner().invoke(
            cli, ["org", "register-device", *args],
            env={"HUBBLE_ORG_ID": "o", "HUBBLE_API_TOKEN": "t"},
        )
    return result, org


class TestRegisterDeviceClaimOption:
    def test_claim_flag_forwarded_and_claim_id_printed(self):
        result, org = _run(["--claim"])
        assert result.exit_code == 0, result.output + str(result.exception)
        kwargs = org.register_device.call_args.kwargs
        assert kwargs["claim"] is True
        assert kwargs["claim_destination_org_id"] is None
        assert "claim_id='d1'" in result.stdout

    def test_claim_destination_org_forwarded(self):
        result, org = _run(["--claim", "--claim-destination-org", ORG])
        assert result.exit_code == 0, result.output + str(result.exception)
        assert org.register_device.call_args.kwargs["claim_destination_org_id"] == ORG

    def test_destination_without_claim_is_usage_error(self):
        result, org = _run(["--claim-destination-org", ORG])
        assert result.exit_code == 2
        assert "--claim-destination-org requires --claim" in result.stderr
        org.register_device.assert_not_called()

    def test_default_does_not_claim(self):
        result, org = _run([])
        assert result.exit_code == 0, result.output + str(result.exception)
        assert org.register_device.call_args.kwargs["claim"] is False


class TestClaimEntitlementError:
    def test_403_on_claim_reports_entitlement_requirements_not_met(self):
        from hubblenetwork.errors import BackendError

        org = MagicMock()
        org.register_device.side_effect = BackendError(
            "403: originating a device claim requires the can_create_device_claims "
            "entitlement for this organization"
        )
        with patch("hubblenetwork.cli.Organization", return_value=org):
            result = CliRunner().invoke(
                cli, ["org", "register-device", "--claim"],
                env={"HUBBLE_ORG_ID": "o", "HUBBLE_API_TOKEN": "t"},
            )
        assert result.exit_code == 1
        assert "entitlement requirements not met" in result.output
        assert "can_create_device_claims" in result.output
