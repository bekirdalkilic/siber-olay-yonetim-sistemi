from collections import deque
from datetime import datetime, timedelta

ESIK = 6  # pencerede bu kadar veya daha fazla başarısız parola denemesi alarm üretir
PENCERE_SANIYE = 60
OLAY_TURU = "ssh_brute_force"


def zaman_coz(zaman_metni, yil):
    """Syslog zamanını ("Nov 21 10:15:03") yıl ekleyerek datetime'a çevirir.

    Zaman yoksa veya bozuksa None döndürür.
    """
    if zaman_metni is None:
        return None
    try:
        return datetime.strptime(f"{yil} {zaman_metni}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def basarisiz_parola_mi(olay):
    return olay["durum"] == "basarisiz" and olay["yontem"] == "password"


def detect_ssh_bruteforce(olaylar, yil, esik=ESIK, pencere_saniye=PENCERE_SANIYE):
    """parse_sshd_line çıktılarından SSH brute-force alarmları üretir.

    olaylar: parse_sshd_line sonuçları (None olanlar atlanır, sırasız olabilir)
    yil: syslog'da yıl olmadığı için dışarıdan verilen yıl
    Dönüş: alarm sözlüklerinden oluşan liste
    """
    pencere_suresi = timedelta(seconds=pencere_saniye)

    # 1) Sadece sayılacak olayları (zaman, ip) olarak topla.
    denemeler = []
    for olay in olaylar:
        if olay is None or not basarisiz_parola_mi(olay):
            continue  # bu olayı atla, sonraki tura geç
        zaman = zaman_coz(olay["zaman"], yil)
        if zaman is None:
            continue
        denemeler.append((zaman, olay["kaynak_ip"]))

    # 2) Kayıtlar sırasız gelebilir: log zamanına göre sırala.
    denemeler.sort()

    # 3) Her IP için ayrı kayan pencere.
    pencereler = {}  # ip -> o IP'nin penceredeki deneme zamanları
    alarmdaki_ipler = set()
    alarmlar = []

    for zaman, ip in denemeler:
        if ip not in pencereler:
            pencereler[ip] = deque()
        pencere = pencereler[ip]

        pencere.append(zaman)
        # Baştan, 60 saniyeden eski denemeleri at.
        # (Döngü hep durur: en son eklenen deneme kendisinden 0 sn uzaktadır.)
        while zaman - pencere[0] > pencere_suresi:
            pencere.popleft()

        if len(pencere) >= esik:
            if ip not in alarmdaki_ipler:
                alarmdaki_ipler.add(ip)
                alarmlar.append({
                    "kaynak_ip": ip,
                    "olay_turu": OLAY_TURU,
                    "deneme_sayisi": len(pencere),
                    "tespit_zamani": zaman,
                })
        else:
            alarmdaki_ipler.discard(ip)  # saldırı yatıştı, yeni saldırı yeni alarm verebilir

    return alarmlar
