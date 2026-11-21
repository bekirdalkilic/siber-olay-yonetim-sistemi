from pathlib import Path

import pytest

from src.log_reader import read_log_lines
from src.ssh_parser import parse_sshd_line

BASARISIZ = "Nov 21 10:15:03 demo-host sshd[2101]: Failed password for root from 203.0.113.5 port 40224 ssh2"
GECERSIZ_KULLANICI = "Nov 21 10:15:01 demo-host sshd[2101]: Failed password for invalid user admin from 203.0.113.5 port 40222 ssh2"
BASARILI = "Nov 21 10:15:09 demo-host sshd[2105]: Accepted password for deneme from 198.51.100.7 port 51000 ssh2"
ORNEK_LOG = Path(__file__).resolve().parent.parent / "data" / "ssh_sample.log"


def test_basarisiz_giris():
    assert parse_sshd_line(BASARISIZ) == {
        "zaman": "Nov 21 10:15:03",
        "durum": "basarisiz",
        "yontem": "password",
        "kullanici": "root",
        "gecersiz_kullanici": False,
        "kaynak_ip": "203.0.113.5",
        "kaynak_port": 40224,
    }


def test_gecersiz_kullanici_ile_basarisiz_giris():
    sonuc = parse_sshd_line(GECERSIZ_KULLANICI)

    assert sonuc["durum"] == "basarisiz"
    assert sonuc["kullanici"] == "admin"
    assert sonuc["gecersiz_kullanici"] is True
    assert sonuc["kaynak_ip"] == "203.0.113.5"
    assert sonuc["kaynak_port"] == 40222


def test_basarili_giris():
    sonuc = parse_sshd_line(BASARILI)

    assert sonuc["durum"] == "basarili"
    assert sonuc["kullanici"] == "deneme"
    assert sonuc["gecersiz_kullanici"] is False
    assert sonuc["kaynak_ip"] == "198.51.100.7"
    assert sonuc["kaynak_port"] == 51000


def test_ilgisiz_satirlar_none_dondurur():
    nftables = "Nov 21 10:15:05 demo-host kernel: IN=eth0 SRC=203.0.113.5 DST=10.0.0.2 PROTO=TCP SPT=51000 DPT=22"
    sshd_baska_mesaj = "Nov 21 10:00:00 demo-host sshd[900]: Server listening on 0.0.0.0 port 22."

    assert parse_sshd_line(nftables) is None
    assert parse_sshd_line(sshd_baska_mesaj) is None
    assert parse_sshd_line("") is None


def test_bozuk_ip_none_dondurur():
    bozuk = "Nov 21 10:15:03 demo-host sshd[2101]: Failed password for root from 999.999.1.1 port 40224 ssh2"

    assert parse_sshd_line(bozuk) is None


def test_zaman_yoksa_zaman_none_olur():
    zamansiz = "sshd[2101]: Failed password for root from 203.0.113.5 port 40224 ssh2"
    sonuc = parse_sshd_line(zamansiz)

    assert sonuc is not None
    assert sonuc["zaman"] is None
    assert sonuc["kaynak_ip"] == "203.0.113.5"


def test_ipv6_adresi_kabul_edilir():
    ipv6 = "Nov 21 10:15:03 demo-host sshd[2101]: Failed password for root from 2001:db8::1 port 40224 ssh2"
    sonuc = parse_sshd_line(ipv6)

    assert sonuc["kaynak_ip"] == "2001:db8::1"


def test_ornek_log_dosyasi_ile_birlikte():
    kayitlar = read_log_lines(ORNEK_LOG)
    sonuclar = [parse_sshd_line(kayit["ham"]) for kayit in kayitlar]

    assert [s["durum"] for s in sonuclar] == ["basarisiz", "basarisiz", "basarili", "basarisiz"]


def port_satiri(port):
    return f"Nov 21 10:15:03 demo-host sshd[2101]: Failed password for root from 203.0.113.5 port {port} ssh2"


def test_publickey_ile_basarili_giris():
    satir = "Nov 21 10:20:00 demo-host sshd[2200]: Accepted publickey for ogrenci from 198.51.100.7 port 51000 ssh2: RSA SHA256:abcdef"
    sonuc = parse_sshd_line(satir)

    assert sonuc["durum"] == "basarili"
    assert sonuc["yontem"] == "publickey"
    assert sonuc["kullanici"] == "ogrenci"


def test_keyboard_interactive_yontemi_tam_okunur():
    satir = "Nov 21 10:21:00 demo-host sshd[2201]: Failed keyboard-interactive/pam for root from 203.0.113.5 port 40224 ssh2"
    sonuc = parse_sshd_line(satir)

    assert sonuc["durum"] == "basarisiz"
    assert sonuc["yontem"] == "keyboard-interactive/pam"


@pytest.mark.parametrize("port", ["1", "22", "65535"])
def test_gecerli_portlar_tam_okunur(port):
    sonuc = parse_sshd_line(port_satiri(port))

    assert sonuc["kaynak_port"] == int(port)


@pytest.mark.parametrize("port", ["0", "65536", "99999999999", "40224abc"])
def test_gecersiz_portlar_none_dondurur(port):
    assert parse_sshd_line(port_satiri(port)) is None
