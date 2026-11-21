from pathlib import Path

import pytest

from src.log_reader import read_log_lines
from src.nft_parser import parse_nft_line

ORNEK_LOG = Path(__file__).resolve().parent.parent / "data" / "nft_sample.log"


def nft_satiri(src="203.0.113.5", dst="10.0.0.2", proto="TCP", spt="51000", dpt="22", bayrak="SYN"):
    """Geçerli bir nftables log satırı üretir; istenen alan değiştirilebilir."""
    return (
        "Nov 21 10:30:01 demo-host kernel: NFT_LOG: IN=eth0 OUT= "
        f"SRC={src} DST={dst} LEN=60 TOS=0x00 TTL=52 ID=54321 DF PROTO={proto} "
        f"SPT={spt} DPT={dpt} WINDOW=64240 RES=0x00 {bayrak} URGP=0"
    )


def test_gecerli_tcp_baglantisi():
    assert parse_nft_line(nft_satiri()) == {
        "zaman": "Nov 21 10:30:01",
        "kaynak_ip": "203.0.113.5",
        "hedef_ip": "10.0.0.2",
        "protokol": "TCP",
        "kaynak_port": 51000,
        "hedef_port": 22,
        "tcp_bayraklari": ["SYN"],
    }


def test_spt_ve_dpt_karismaz():
    sonuc = parse_nft_line(nft_satiri(spt="22", dpt="51000"))

    assert sonuc["kaynak_port"] == 22
    assert sonuc["hedef_port"] == 51000


@pytest.mark.parametrize("bayrak, beklenen", [
    ("SYN", ["SYN"]),
    ("SYN ACK", ["SYN", "ACK"]),
    ("ACK", ["ACK"]),
    ("", []),
])
def test_tcp_bayraklari_yalniz_logda_yazanlar_doner(bayrak, beklenen):
    assert parse_nft_line(nft_satiri(bayrak=bayrak))["tcp_bayraklari"] == beklenen


def test_udp_baglantisi():
    sonuc = parse_nft_line(nft_satiri(proto="UDP", spt="53124", dpt="53", bayrak=""))

    assert sonuc["protokol"] == "UDP"
    assert sonuc["kaynak_port"] == 53124
    assert sonuc["hedef_port"] == 53
    assert sonuc["tcp_bayraklari"] == []


def test_icmp_portsuz_satir_kabul_edilir():
    satir = "Nov 21 10:30:16 demo-host kernel: NFT_LOG: IN=eth0 OUT= SRC=198.51.100.7 DST=10.0.0.2 LEN=84 TTL=64 ID=1 PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1"
    sonuc = parse_nft_line(satir)

    assert sonuc["protokol"] == "ICMP"
    assert sonuc["kaynak_port"] is None
    assert sonuc["hedef_port"] is None


def test_ipv6_adresleri_normallestirilir():
    sonuc = parse_nft_line(nft_satiri(
        src="2001:0db8:0000:0000:0000:0000:0000:0001",
        dst="2001:0db8:0000:0000:0000:0000:0000:0002",
    ))

    assert sonuc["kaynak_ip"] == "2001:db8::1"
    assert sonuc["hedef_ip"] == "2001:db8::2"


@pytest.mark.parametrize("satir", [
    nft_satiri(src="999.999.1.1"),
    nft_satiri(dst="10.0.0"),
    nft_satiri(src="abc"),
    nft_satiri(dst=""),
])
def test_hatali_ip_none_dondurur(satir):
    assert parse_nft_line(satir) is None


@pytest.mark.parametrize("satir", [
    nft_satiri(spt="0"),
    nft_satiri(dpt="0"),
    nft_satiri(spt="65536"),
    nft_satiri(dpt="65536"),
    nft_satiri(dpt="99999999999"),
    nft_satiri(dpt="abc"),
    nft_satiri(dpt="22x"),
    nft_satiri(spt="-1"),
    nft_satiri(dpt=""),
])
def test_gecersiz_port_none_dondurur(satir):
    assert parse_nft_line(satir) is None


@pytest.mark.parametrize("port", ["1", "65535"])
def test_sinir_portlari_gecerlidir(port):
    sonuc = parse_nft_line(nft_satiri(spt=port, dpt=port))

    assert sonuc["kaynak_port"] == int(port)
    assert sonuc["hedef_port"] == int(port)


@pytest.mark.parametrize("eksik_parca", [
    "SRC=203.0.113.5 ",
    "DST=10.0.0.2 ",
    "PROTO=TCP ",
    "SPT=51000 ",
    "DPT=22 ",
])
def test_eksik_alan_none_dondurur(eksik_parca):
    satir = nft_satiri()

    assert eksik_parca in satir  # silinecek parça gerçekten satırda olmalı
    assert parse_nft_line(satir.replace(eksik_parca, "")) is None


def test_ilgisiz_satirlar_none_dondurur():
    usb = "Nov 21 10:30:21 demo-host kernel: usb 1-1: new high-speed USB device number 3 using xhci_hcd"
    baska_prefix = nft_satiri().replace("NFT_LOG:", "IPT_DROP:")
    ssh = "Nov 21 10:15:03 demo-host sshd[2101]: Failed password for root from 203.0.113.5 port 40224 ssh2"
    sadece_prefix = "Nov 21 10:30:01 demo-host kernel: NFT_LOG:"

    for satir in (usb, baska_prefix, ssh, sadece_prefix, ""):
        assert parse_nft_line(satir) is None


def test_zaman_ham_metin_olarak_korunur_yil_eklenmez():
    assert parse_nft_line(nft_satiri())["zaman"] == "Nov 21 10:30:01"


def test_zaman_yoksa_zaman_none_olur():
    satir = nft_satiri().replace("Nov 21 10:30:01 demo-host ", "")
    sonuc = parse_nft_line(satir)

    assert sonuc is not None
    assert sonuc["zaman"] is None
    assert sonuc["hedef_port"] == 22


def test_dmesg_sayaci_olan_satir_ayrisir():
    satir = nft_satiri().replace("kernel: NFT_LOG:", "kernel: [ 1234.567890] NFT_LOG:")
    sonuc = parse_nft_line(satir)

    assert sonuc["zaman"] == "Nov 21 10:30:01"
    assert sonuc["kaynak_ip"] == "203.0.113.5"
    assert sonuc["hedef_port"] == 22


def test_tekrarlanan_alanlarda_ilk_deger_kullanilir():
    satir = nft_satiri() + " SRC=192.0.2.1 DST=192.0.2.2"
    sonuc = parse_nft_line(satir)

    assert sonuc["kaynak_ip"] == "203.0.113.5"
    assert sonuc["hedef_ip"] == "10.0.0.2"


def test_ornek_log_read_log_lines_ile_uyumlu():
    kayitlar = read_log_lines(ORNEK_LOG)
    sonuclar = [parse_nft_line(kayit["ham"]) for kayit in kayitlar]
    taninanlar = [s for s in sonuclar if s is not None]

    assert len(kayitlar) == 18  # 19 satır, 1 boş satır atlandı
    assert kayitlar[13]["satir_no"] == 15  # boş satırdan sonraki kaydın gerçek numarası
    assert len(taninanlar) == 15  # 3 ilgisiz kernel satırı None oldu


def test_ornek_log_tarama_trafigi_ve_diger_protokoller():
    kayitlar = read_log_lines(ORNEK_LOG)
    taninanlar = [parse_nft_line(kayit["ham"]) for kayit in kayitlar]
    taninanlar = [s for s in taninanlar if s is not None]

    tarayici = [s for s in taninanlar if s["kaynak_ip"] == "203.0.113.5"]
    assert {s["hedef_port"] for s in tarayici} == {21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 8080}
    assert all(s["tcp_bayraklari"] == ["SYN"] for s in tarayici)

    diger = [s for s in taninanlar if s["kaynak_ip"] == "198.51.100.7"]
    assert sorted(s["protokol"] for s in diger) == ["ICMP", "TCP", "UDP"]
    tcp = [s for s in diger if s["protokol"] == "TCP"][0]
    assert tcp["tcp_bayraklari"] == ["ACK"]  # SYN yok, SYN varsayılmadı
