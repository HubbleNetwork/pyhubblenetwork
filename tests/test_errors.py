"""Unit tests for HTTP-status → exception mapping."""
from hubblenetwork.errors import BackendError, NotFoundError, map_http_status


def test_404_maps_to_not_found_error():
    err = map_http_status(404, "device missing")
    assert isinstance(err, NotFoundError)
    assert isinstance(err, BackendError)  # backward-compatible subclass


def test_404_message_includes_status_and_detail():
    err = map_http_status(404, "device missing")
    assert "404" in str(err)
    assert "device missing" in str(err)


def test_400_still_maps_to_request_error():
    from hubblenetwork.errors import RequestError

    assert isinstance(map_http_status(400, "bad"), RequestError)
