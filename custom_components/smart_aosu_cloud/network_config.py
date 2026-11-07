"""Narrow LAN address validation shared by HA config and options flows."""
from __future__ import annotations
from ipaddress import IPv4Address, IPv4Network

NETWORKS = (IPv4Network("10.0.0.0/8"), IPv4Network("172.16.0.0/12"),
            IPv4Network("192.168.0.0/16"))


def optional_station_ip(value: object) -> str:
    """Return a canonical RFC1918 IPv4 address or '' for unset."""
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or len(value) > 15:
        raise ValueError("invalid_station_ip")
    if value != value.strip():
        raise ValueError("invalid_station_ip")
    try:
        address = IPv4Address(value)
    except ValueError as exc:
        raise ValueError("invalid_station_ip") from exc
    if not any(address in network for network in NETWORKS) or str(address) != value:
        raise ValueError("invalid_station_ip")
    return str(address)
