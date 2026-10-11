"""Tests for nmap XML parsing."""

from shadowreap.scanners.ports import parse_nmap_xml

XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" version="OpenSSH 9.2"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parses_open_ports_only():
    res = parse_nmap_xml(XML)
    assert len(res) == 3
    p22, p443, p445 = res[0], res[1], res[2]
    assert p22.host == "10.0.0.1" and p22.port == 22 and p22.service == "ssh"
    assert p22.version == "OpenSSH 9.2"
    assert p443.port == 443 and p443.service == "https"
    assert p445.host == "10.0.0.2"

    # closed 80 must NOT appear
    assert not any(p.port == 80 for p in res)


def test_empty_xml():
    assert parse_nmap_xml("<nmaprun/>") == []