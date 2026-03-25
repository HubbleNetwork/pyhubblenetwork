"""
Satellite scanning via PlutoSDR Docker container.

Manages the Docker container lifecycle (pull, start, stop) and polls
the HTTP API for decoded satellite packets.

Requires the ``docker`` Python SDK (``pip install docker``).
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Generator, List, Optional, Set, Tuple

import httpx

from .errors import DockerError, SatelliteError
from .packets import SatellitePacket

logger = logging.getLogger(__name__)

DOCKER_IMAGE = "ghcr.io/hubblenetwork/pluto-sdr-docker:latest"
CONTAINER_NAME = "hubble-pluto-sdr"
API_PORT = 8050
_CONTAINER_INTERNAL_PORT = 8050  # fixed by the Docker image


def _packets_url(port: int = API_PORT) -> str:
    return f"http://localhost:{port}/api/packets"


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------


def _get_client():
    """Return a Docker client from the environment.

    Raises ``DockerError`` if the Docker SDK is not installed.
    """
    try:
        import docker
    except ImportError:
        raise DockerError(
            "The 'docker' Python package is required for satellite scanning. "
            "Install it with: pip install docker"
        )
    try:
        return docker.from_env()
    except docker.errors.DockerException:
        raise DockerError("Docker is not available")


def ensure_docker_available() -> None:
    """Verify that Docker is installed and the daemon is running."""
    client = _get_client()
    try:
        client.ping()
    except Exception:
        raise DockerError("Docker daemon is not responding")


def pull_image(image: str = DOCKER_IMAGE) -> None:
    """Pull *image*, ensuring the latest version is fetched."""
    logger.info("Pulling %s …", image)
    client = _get_client()
    try:
        client.images.pull(image)
    except Exception as exc:
        raise DockerError(f"Failed to pull image {image}: {exc}")


def start_container(
    image: str = DOCKER_IMAGE,
    port: int = API_PORT,
) -> str:
    """Start the PlutoSDR container and return the container ID.

    The container is started with ``auto_remove=True`` so it is
    automatically removed when stopped.
    """
    client = _get_client()
    try:
        container = client.containers.run(
            image,
            detach=True,
            auto_remove=True,
            ports={f"{_CONTAINER_INTERNAL_PORT}/tcp": port},
            name=CONTAINER_NAME,
            privileged=True,
        )
        logger.debug("Started container %s", container.short_id)
        return container.id
    except Exception as exc:
        raise DockerError(f"Failed to start container: {exc}")


def stop_container(container_id: str) -> None:
    """Stop *container_id* (best-effort, errors are swallowed)."""
    try:
        client = _get_client()
        container = client.containers.get(container_id)
        container.stop(timeout=10)
    except Exception:
        pass  # best-effort cleanup


# ---------------------------------------------------------------------------
# HTTP API helpers
# ---------------------------------------------------------------------------


def _wait_for_api(port: int = API_PORT, timeout: float = 30) -> None:
    """Block until the packet API responds or *timeout* seconds elapse."""
    deadline = time.monotonic() + timeout
    url = _packets_url(port)
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(url, timeout=2)
            if resp.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    raise SatelliteError(
        f"Satellite receiver API did not become ready within {timeout}s"
    )


def _parse_jsonl(text: str) -> List[SatellitePacket]:
    """Parse a JSONL response body into a list of ``SatellitePacket``."""
    packets: List[SatellitePacket] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            payload_b64 = obj.get("payload", "")
            payload = base64.b64decode(payload_b64) if payload_b64 else b""
            packets.append(
                SatellitePacket(
                    device_id=obj["device_id"],
                    seq_num=obj["seq_num"],
                    device_type=obj["device_type"],
                    timestamp=obj["timestamp"],
                    rssi_dB=obj["rssi_dB"],
                    channel_num=obj["channel_num"],
                    freq_offset_hz=obj["freq_offset_hz"],
                    payload=payload,
                )
            )
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            logger.warning("Skipping malformed packet line: %s (%s)", line, exc)
    return packets


def fetch_packets(port: int = API_PORT) -> List[SatellitePacket]:
    """Fetch the current packet buffer from the satellite receiver API."""
    url = _packets_url(port)
    try:
        resp = httpx.get(url, timeout=5)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise SatelliteError(f"Failed to fetch packets from {url}: {exc}")
    return _parse_jsonl(resp.text)


# ---------------------------------------------------------------------------
# High-level scanning
# ---------------------------------------------------------------------------


def _packet_key(pkt: SatellitePacket) -> Tuple[str, int]:
    """Return a deduplication key for *pkt*."""
    return (pkt.device_id, pkt.seq_num)


def scan(
    timeout: Optional[float] = None,
    poll_interval: float = 2.0,
    port: int = API_PORT,
    image: str = DOCKER_IMAGE,
) -> Generator[SatellitePacket, None, None]:
    """Scan for satellite packets, managing the Docker container lifecycle.

    Yields new ``SatellitePacket`` objects as they are discovered.  The
    container is guaranteed to be stopped when the generator is closed or
    an exception occurs.
    """
    ensure_docker_available()
    pull_image(image)

    container_id = start_container(image=image, port=port)
    try:
        _wait_for_api(port=port)

        seen: Set[Tuple[str, int]] = set()
        start = time.monotonic()
        deadline = None if timeout is None else start + timeout

        while deadline is None or time.monotonic() < deadline:
            packets = fetch_packets(port=port)
            for pkt in packets:
                key = _packet_key(pkt)
                if key not in seen:
                    seen.add(key)
                    yield pkt

            # Sleep between polls, but respect the deadline
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(poll_interval, remaining))
            else:
                time.sleep(poll_interval)
    finally:
        stop_container(container_id)
