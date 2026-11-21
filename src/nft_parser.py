import ipaddress
import re

# nftables kuralındaki log prefix'i. Örn: log prefix "NFT_LOG: "
NFT_PREFIX = "NFT_LOG:"

# Syslog zamanı satırın başındadır; yıl yoktur, ham metin olarak saklanır.
# (SSH parser'dan bağımsız kalsın diye burada ayrıca tanımlandı.)
ZAMAN_DESENI = re.compile(r"^(?P<zaman>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

PORTLU_PROTOKOLLER = {"TCP", "UDP"}
TCP_BAYRAKLARI = {"SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"}


def port_coz(metin):
    """'51000' -> 51000. Rakam değilse veya 1-65535 dışındaysa None."""
    if not (metin.isascii() and metin.isdigit()):
        return None
    port = int(metin)
    if not 1 <= port <= 65535:
        return None
    return port


def parse_nft_line(line):
    """Tek bir nftables (kernel) log satırını sözlüğe çevirir.

    Satırda NFT_PREFIX yoksa, gerekli alanlar eksikse veya IP/port bozuksa None döndürür.
    """
    if NFT_PREFIX not in line:
        return None

    # 1) Prefix'ten sonrasını boşluklardan böl, KEY=VALUE çiftlerini sözlüğe koy.
    sonrasi = line.split(NFT_PREFIX, 1)[1]
    alanlar = {}
    gorulen_bayraklar = []
    for parca in sonrasi.split():
        if "=" in parca:
            anahtar, deger = parca.split("=", 1)
            if anahtar not in alanlar:  # tekrar eden alanlarda ilk değer kalır
                alanlar[anahtar] = deger
        elif parca in TCP_BAYRAKLARI:
            gorulen_bayraklar.append(parca)

    # 2) Zorunlu alanlar eksik veya boşsa satır geçersiz.
    for ad in ("SRC", "DST", "PROTO"):
        if not alanlar.get(ad):
            return None

    # 3) IP adreslerini doğrula.
    try:
        kaynak_ip = ipaddress.ip_address(alanlar["SRC"])
        hedef_ip = ipaddress.ip_address(alanlar["DST"])
    except ValueError:
        return None

    # 4) Portlar yalnızca TCP/UDP'de vardır. SPT = kaynak port, DPT = hedef port.
    protokol = alanlar["PROTO"]
    kaynak_port = None
    hedef_port = None
    if protokol in PORTLU_PROTOKOLLER:
        kaynak_port = port_coz(alanlar.get("SPT", ""))
        hedef_port = port_coz(alanlar.get("DPT", ""))
        if kaynak_port is None or hedef_port is None:
            return None

    # 5) TCP bayrakları: yalnızca logda yazanlar. SYN logda yoksa SYN varsayılmaz.
    if protokol == "TCP":
        tcp_bayraklari = gorulen_bayraklar
    else:
        tcp_bayraklari = []

    zaman_eslesmesi = ZAMAN_DESENI.search(line)
    if zaman_eslesmesi is None:
        zaman = None
    else:
        zaman = zaman_eslesmesi.group("zaman")

    return {
        "zaman": zaman,
        "kaynak_ip": str(kaynak_ip),
        "hedef_ip": str(hedef_ip),
        "protokol": protokol,
        "kaynak_port": kaynak_port,
        "hedef_port": hedef_port,
        "tcp_bayraklari": tcp_bayraklari,
    }
