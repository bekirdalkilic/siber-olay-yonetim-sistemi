import ipaddress
import re

# Syslog zamanı satırın başındadır: "Nov 21 10:15:01". Yıl yoktur, ham metin olarak saklarız.
ZAMAN_DESENI = re.compile(r"^(?P<zaman>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

# sshd mesajı: "Failed|Accepted YONTEM for [invalid user ]KULLANICI from IP port PORT"
SSH_DESENI = re.compile(
    r"(?P<durum>Failed|Accepted) (?P<yontem>\S+) for "
    r"(?P<gecersiz>invalid user )?"
    r"(?P<kullanici>\S+) "
    r"from (?P<ip>\S+) "
    r"port (?P<port>\d+)\b"
)

DURUM_ADLARI = {"Failed": "basarisiz", "Accepted": "basarili"}


def parse_sshd_line(line):
    """Tek bir sshd log satırını sözlüğe çevirir.

    Tanınmayan veya bozuk satırda (ör. geçersiz IP veya port) None döndürür.
    """
    eslesme = SSH_DESENI.search(line)
    if eslesme is None:
        return None

    port = int(eslesme.group("port"))
    if not 1 <= port <= 65535:
        return None

    try:
        ip = ipaddress.ip_address(eslesme.group("ip"))
    except ValueError:
        return None

    zaman_eslesmesi = ZAMAN_DESENI.search(line)
    if zaman_eslesmesi is None:
        zaman = None
    else:
        zaman = zaman_eslesmesi.group("zaman")

    return {
        "zaman": zaman,
        "durum": DURUM_ADLARI[eslesme.group("durum")],
        "yontem": eslesme.group("yontem"),
        "kullanici": eslesme.group("kullanici"),
        "gecersiz_kullanici": eslesme.group("gecersiz") is not None,
        "kaynak_ip": str(ip),
        "kaynak_port": port,
    }
