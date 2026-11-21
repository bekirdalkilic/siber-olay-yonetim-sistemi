from collections import deque
from datetime import timedelta

from src.ssh_detector import zaman_coz

ESIK = 11  # pencerede bu kadar veya daha fazla FARKLI hedef port alarm üretir
PENCERE_SANIYE = 10
OLAY_TURU = "port_scan"


def baslangic_syn_mi(olay):
    """TCP paketinde SYN var ve ACK yoksa True (bağlantı başlatma denemesi)."""
    if olay.get("protokol") != "TCP":
        return False
    bayraklar = olay.get("tcp_bayraklari") or []
    return "SYN" in bayraklar and "ACK" not in bayraklar


def detect_port_scan(olaylar, yil, esik=ESIK, pencere_saniye=PENCERE_SANIYE):
    """parse_nft_line çıktılarından port taraması alarmları üretir.

    olaylar: parse_nft_line sonuçları (None veya ilgisiz kayıtlar atlanır, sırasız olabilir)
    yil: syslog'da yıl olmadığı için dışarıdan verilen yıl
    Dönüş: alarm sözlüklerinden oluşan liste
    """
    pencere_suresi = timedelta(seconds=pencere_saniye)

    # 1) Sadece sayılacak SYN kayıtlarını (zaman, kaynak, hedef, port) olarak topla.
    denemeler = []
    for olay in olaylar:
        if olay is None or not baslangic_syn_mi(olay):
            continue  # bu kaydı atla, sonraki tura geç
        zaman = zaman_coz(olay["zaman"], yil)
        if zaman is None:
            continue
        denemeler.append((zaman, olay["kaynak_ip"], olay["hedef_ip"], olay["hedef_port"]))

    # 2) Kayıtlar sırasız gelebilir: log zamanına göre sırala.
    denemeler.sort()

    # 3) Her (kaynak_ip, hedef_ip) çifti için ayrı kayan pencere.
    pencereler = {}       # cift -> deque([(zaman, port), ...])
    port_sayaclari = {}   # cift -> {port: penceredeki deneme sayısı}
    alarmdaki_ciftler = set()
    alarmlar = []

    for zaman, kaynak_ip, hedef_ip, port in denemeler:
        cift = (kaynak_ip, hedef_ip)
        if cift not in pencereler:
            pencereler[cift] = deque()
            port_sayaclari[cift] = {}
        pencere = pencereler[cift]
        sayac = port_sayaclari[cift]

        # Yeni SYN'i pencereye ekle ve portunun sayacını artır.
        pencere.append((zaman, port))
        sayac[port] = sayac.get(port, 0) + 1

        # Baştan, 10 saniyeden eski kayıtları at ve sayaçlarını düşür.
        # (Döngü hep durur: en son eklenen kayıt kendisinden 0 sn uzaktadır.)
        while zaman - pencere[0][0] > pencere_suresi:
            eski_port = pencere.popleft()[1]
            sayac[eski_port] -= 1
            if sayac[eski_port] == 0:
                del sayac[eski_port]  # o porta penceredeki son deneme de düştü

        if len(sayac) >= esik:  # len(sayac) = penceredeki FARKLI port sayısı
            if cift not in alarmdaki_ciftler:
                alarmdaki_ciftler.add(cift)
                alarmlar.append({
                    "kaynak_ip": kaynak_ip,
                    "hedef_ip": hedef_ip,
                    "olay_turu": OLAY_TURU,
                    "farkli_port_sayisi": len(sayac),
                    "ilk_gorulme": pencere[0][0],
                    "tespit_zamani": zaman,
                })
        else:
            alarmdaki_ciftler.discard(cift)  # tarama yatıştı, yenisi yeni alarm verebilir

    return alarmlar
