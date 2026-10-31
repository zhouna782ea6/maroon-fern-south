"""通过真实 SOCKS5 通道检查 TCP、UDP 和公网 IPv4。"""
import ipaddress
import os
import socket
import struct
import subprocess

PORT = 1080
TIMEOUT = 8
STUN_COOKIE = 0x2112A442
STUN_HOST = "stun.l.google.com"
STUN_PORT = 19302


def exact(stream, length):
    data = b""
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise RuntimeError("socks_closed")
        data += chunk
    return data


def socks_address(stream):
    kind = exact(stream, 1)[0]
    if kind != 1:
        raise RuntimeError("socks_ipv4_required")
    host = socket.inet_ntoa(exact(stream, 4))
    port = struct.unpack("!H", exact(stream, 2))[0]
    return host, port


def associate(host):
    control = socket.create_connection((host, PORT), timeout=TIMEOUT)
    try:
        control.sendall(b"\x05\x01\x00")
        if exact(control, 2) != b"\x05\x00":
            raise RuntimeError("socks_auth_failed")
        control.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
        if exact(control, 3) != b"\x05\x00\x00":
            raise RuntimeError("socks_udp_failed")
        relay, port = socks_address(control)
        if relay == "0.0.0.0":
            relay = host
        if relay != host or not port:
            raise RuntimeError("socks_relay_unreachable")
        return control, (relay, port)
    except BaseException:
        control.close()
        raise


def stun_ip(data, transaction):
    if len(data) < 20:
        raise RuntimeError("stun_short")
    kind, length, cookie = struct.unpack("!HHI", data[:8])
    if kind != 0x0101 or cookie != STUN_COOKIE or data[8:20] != transaction:
        raise RuntimeError("stun_invalid")
    if length % 4 or len(data) != 20 + length:
        raise RuntimeError("stun_length_invalid")
    offset = 20
    while offset + 4 <= len(data):
        attribute, size = struct.unpack("!HH", data[offset:offset + 4])
        value = data[offset + 4:offset + 4 + size]
        if len(value) != size:
            raise RuntimeError("stun_attribute_invalid")
        if attribute == 0x0020 and size == 8 and value[1] == 1:
            address = struct.unpack("!I", value[4:8])[0] ^ STUN_COOKIE
            return socket.inet_ntoa(struct.pack("!I", address))
        offset += 4 + ((size + 3) // 4) * 4
    raise RuntimeError("stun_address_missing")


def udp_ip(host):
    control, relay = associate(host)
    try:
        destination = socket.gethostbyname(STUN_HOST)
        transaction = os.urandom(12)
        request = struct.pack("!HHI", 1, 0, STUN_COOKIE) + transaction
        header = b"\x00\x00\x00\x01" + socket.inet_aton(destination)
        header += struct.pack("!H", STUN_PORT)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(TIMEOUT)
            stream.connect(relay)
            stream.send(header + request)
            reply = stream.recv(65535)
        if len(reply) < 10 or reply[:4] != b"\x00\x00\x00\x01":
            raise RuntimeError("socks_udp_packet_invalid")
        if reply[4:10] != header[4:10]:
            raise RuntimeError("socks_udp_source_invalid")
        return stun_ip(reply[10:], transaction)
    finally:
        control.close()


def check(host):
    result = subprocess.run([
        "curl", "--fail", "--silent", "--show-error", "--max-time", str(TIMEOUT),
        "--socks5-hostname", f"{host}:{PORT}", "https://api.ipify.org",
    ], check=True, capture_output=True, timeout=TIMEOUT + 2)
    tcp = result.stdout.decode("ascii").strip()
    if not ipaddress.IPv4Address(tcp).is_global:
        raise RuntimeError("public_ipv4_required")
    if udp_ip(host) != tcp:
        raise RuntimeError("tcp_udp_egress_mismatch")
    return tcp
