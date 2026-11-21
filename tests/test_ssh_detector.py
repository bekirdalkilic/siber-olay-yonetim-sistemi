from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.log_reader import read_log_lines
from src.ssh_detector import detect_ssh_bruteforce, zaman_coz
from src.ssh_parser import parse_sshd_line

BASLANGIC = datetime(2026, 11, 21, 10, 0, 0)
IP_A = "203.0.113.5"
IP_B = "198.51.100.9"
ORNEK_LOG = Path(__file__).resolve().parent.parent / "data" / "ssh_sample.log"


def olay(saniye, ip=IP_A, durum="basarisiz", yontem="password"):
    """BASLANGIC'tan 'saniye' sonrasına ait, parse_sshd_line biçiminde bir olay üretir."""
    zaman = (BASLANGIC + timedelta(seconds=saniye)).strftime("%b %d %H:%M:%S")
    return {"zaman": zaman, "durum": durum, "yontem": yontem, "kaynak_ip": ip}


def tespit(olaylar):
    return detect_ssh_bruteforce(olaylar, yil=2026)


def test_alti_basarisiz_parola_alarm_uretir():
    alarmlar = tespit([olay(s) for s in range(6)])

    assert alarmlar == [{
        "kaynak_ip": IP_A,
        "olay_turu": "ssh_brute_force",
        "deneme_sayisi": 6,
        "tespit_zamani": datetime(2026, 11, 21, 10, 0, 5),
    }]


def test_bes_basarisiz_parola_alarm_uretmez():
    assert tespit([olay(s) for s in range(5)]) == []


def test_farkli_ipler_birbirine_eklenmez():
    olaylar = []
    for s in range(3):
        olaylar.append(olay(s, ip=IP_A))
        olaylar.append(olay(s, ip=IP_B))

    assert tespit(olaylar) == []  # toplam 6, ama IP başına 3


def test_alarm_sadece_saldiran_ip_icin_uretilir():
    olaylar = [olay(s, ip=IP_A) for s in range(6)] + [olay(s, ip=IP_B) for s in range(2)]
    alarmlar = tespit(olaylar)

    assert len(alarmlar) == 1
    assert alarmlar[0]["kaynak_ip"] == IP_A


def test_basarili_giris_sayilmaz():
    olaylar = [olay(s) for s in range(5)] + [olay(5, durum="basarili")]

    assert tespit(olaylar) == []


@pytest.mark.parametrize("yontem", ["publickey", "keyboard-interactive/pam"])
def test_parola_disindaki_yontemler_sayilmaz(yontem):
    olaylar = [olay(s) for s in range(5)] + [olay(5, yontem=yontem)]

    assert tespit(olaylar) == []


@pytest.mark.parametrize("son_saniye, beklenen_alarm", [(60, 1), (61, 0)])
def test_60_saniye_siniri(son_saniye, beklenen_alarm):
    olaylar = [olay(s) for s in (0, 10, 20, 30, 40)] + [olay(son_saniye)]

    assert len(tespit(olaylar)) == beklenen_alarm


def test_sirasiz_kayitlar_dogru_islenir():
    karisik = [olay(s) for s in (30, 0, 20, 10, 5, 25)]
    alarmlar = tespit(karisik)

    assert len(alarmlar) == 1
    assert alarmlar[0]["tespit_zamani"] == datetime(2026, 11, 21, 10, 0, 30)
    assert alarmlar == tespit([olay(s) for s in (0, 5, 10, 20, 25, 30)])


def test_ayni_saldiri_icin_tekrar_alarm_uretilmez():
    assert len(tespit([olay(s) for s in range(10)])) == 1


def test_ayri_iki_saldiri_iki_alarm_uretir():
    olaylar = [olay(s) for s in range(6)] + [olay(1000 + s) for s in range(6)]
    alarmlar = tespit(olaylar)

    assert [a["tespit_zamani"] for a in alarmlar] == [
        datetime(2026, 11, 21, 10, 0, 5),
        datetime(2026, 11, 21, 10, 16, 45),
    ]


def test_zamani_olmayan_olay_atlanir():
    zamansiz = {"zaman": None, "durum": "basarisiz", "yontem": "password", "kaynak_ip": IP_A}
    olaylar = [olay(s) for s in range(5)] + [zamansiz]

    assert tespit(olaylar) == []


def test_zaman_coz_yil_ekler():
    assert zaman_coz("Nov 21 10:15:03", 2026) == datetime(2026, 11, 21, 10, 15, 3)


def test_zaman_coz_tek_haneli_gunde_cift_bosluk():
    assert zaman_coz("Nov  5 09:01:02", 2026) == datetime(2026, 11, 5, 9, 1, 2)


def test_zaman_coz_bozuk_veya_yok_none_dondurur():
    assert zaman_coz(None, 2026) is None
    assert zaman_coz("Foo 99 99:99:99", 2026) is None


def test_parser_ciktisiyla_birlikte_calisir():
    satirlar = [
        f"Nov 21 10:15:0{n} demo-host sshd[2101]: Failed password for root from 203.0.113.5 port 4022{n} ssh2"
        for n in range(6)
    ]
    satirlar.append("Nov 21 10:15:07 demo-host kernel: IN=eth0 SRC=203.0.113.5 DST=10.0.0.2 PROTO=TCP SPT=51000 DPT=22")
    olaylar = [parse_sshd_line(satir) for satir in satirlar]  # ilgisiz satır None olur
    alarmlar = tespit(olaylar)

    assert len(alarmlar) == 1
    assert alarmlar[0]["kaynak_ip"] == "203.0.113.5"
    assert alarmlar[0]["deneme_sayisi"] == 6


def test_ornek_log_dosyasi_alarm_uretmez():
    kayitlar = read_log_lines(ORNEK_LOG)
    olaylar = [parse_sshd_line(kayit["ham"]) for kayit in kayitlar]

    assert tespit(olaylar) == []  # örnek logda sadece 3 başarısız parola var
