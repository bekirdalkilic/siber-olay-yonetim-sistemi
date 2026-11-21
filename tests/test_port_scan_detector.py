from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.log_reader import read_log_lines
from src.nft_parser import parse_nft_line
from src.port_scan_detector import detect_port_scan

BASLANGIC = datetime(2026, 11, 21, 10, 0, 0)
KAYNAK_A = "203.0.113.5"
KAYNAK_B = "203.0.113.77"
HEDEF_X = "10.0.0.2"
HEDEF_Y = "10.0.0.9"
ORNEK_LOG = Path(__file__).resolve().parent.parent / "data" / "nft_sample.log"


def olay(saniye, port, kaynak=KAYNAK_A, hedef=HEDEF_X, protokol="TCP", bayraklar=("SYN",)):
    """BASLANGIC'tan 'saniye' sonrasına ait, parse_nft_line biçiminde bir olay üretir."""
    zaman = (BASLANGIC + timedelta(seconds=saniye)).strftime("%b %d %H:%M:%S")
    return {
        "zaman": zaman,
        "kaynak_ip": kaynak,
        "hedef_ip": hedef,
        "protokol": protokol,
        "kaynak_port": 40000,
        "hedef_port": port,
        "tcp_bayraklari": list(bayraklar),
    }


def tespit(olaylar):
    return detect_port_scan(olaylar, yil=2026)


def test_on_bir_farkli_port_alarm_uretir():
    alarmlar = tespit([olay(s, 1000 + s) for s in range(11)])

    assert alarmlar == [{
        "kaynak_ip": KAYNAK_A,
        "hedef_ip": HEDEF_X,
        "olay_turu": "port_scan",
        "farkli_port_sayisi": 11,
        "ilk_gorulme": datetime(2026, 11, 21, 10, 0, 0),
        "tespit_zamani": datetime(2026, 11, 21, 10, 0, 10),
    }]


def test_on_farkli_port_alarm_uretmez():
    assert tespit([olay(s, 1000 + s) for s in range(10)]) == []


def test_ayni_porta_tekrarlar_farkli_port_sayilmaz():
    # 10 farklı port, her biri 3 kez = 30 SYN, ama yalnızca 10 farklı port.
    olaylar = [olay(i // 3, 1000 + i % 10) for i in range(30)]

    assert tespit(olaylar) == []


def test_tekrarlar_olsa_da_farkli_port_sayisi_dogru_raporlanir():
    # 11 farklı port, her biri 2 kez = 22 SYN. Rapor 11 olmalı, 22 değil.
    olaylar = [olay(i // 3, 1000 + i % 11) for i in range(22)]
    alarmlar = tespit(olaylar)

    assert len(alarmlar) == 1
    assert alarmlar[0]["farkli_port_sayisi"] == 11


def test_farkli_hedef_ipleri_birlestirilmez():
    # Toplam 12 farklı port, ama hedef başına 6.
    olaylar = [olay(s, 1000 + s, hedef=HEDEF_X) for s in range(6)]
    olaylar += [olay(s, 2000 + s, hedef=HEDEF_Y) for s in range(6)]

    assert tespit(olaylar) == []


def test_farkli_kaynak_ipleri_birlestirilmez():
    olaylar = [olay(s, 1000 + s, kaynak=KAYNAK_A) for s in range(6)]
    olaylar += [olay(s, 2000 + s, kaynak=KAYNAK_B) for s in range(6)]

    assert tespit(olaylar) == []


def test_alarm_sadece_tarayan_cift_icin_uretilir():
    olaylar = [olay(s, 1000 + s, hedef=HEDEF_X) for s in range(11)]
    olaylar += [olay(s, 3000 + s, hedef=HEDEF_Y) for s in range(3)]
    alarmlar = tespit(olaylar)

    assert len(alarmlar) == 1
    assert alarmlar[0]["hedef_ip"] == HEDEF_X


@pytest.mark.parametrize("bayraklar, beklenen_alarm", [
    (["SYN"], 1),
    (["SYN", "ACK"], 0),
    (["ACK"], 0),
    ([], 0),
    (["RST"], 0),
])
def test_syn_ack_ayrimi(bayraklar, beklenen_alarm):
    olaylar = [olay(s, 1000 + s) for s in range(10)] + [olay(10, 1010, bayraklar=bayraklar)]

    assert len(tespit(olaylar)) == beklenen_alarm


def test_tcp_disi_protokoller_sayilmaz():
    # 11. kayıt UDP: SYN bayrağı yazsa bile protokol TCP değilse sayılmaz.
    olaylar = [olay(s, 1000 + s) for s in range(10)] + [olay(10, 1010, protokol="UDP")]

    assert tespit(olaylar) == []


def test_sirasiz_kayitlar_dogru_islenir():
    karisik = [olay(s, 1000 + s) for s in (7, 0, 10, 3, 5, 1, 9, 2, 8, 4, 6)]
    alarmlar = tespit(karisik)

    assert len(alarmlar) == 1
    assert alarmlar[0]["ilk_gorulme"] == datetime(2026, 11, 21, 10, 0, 0)
    assert alarmlar[0]["tespit_zamani"] == datetime(2026, 11, 21, 10, 0, 10)
    assert alarmlar == tespit([olay(s, 1000 + s) for s in range(11)])


@pytest.mark.parametrize("son_saniye, beklenen_alarm", [(10, 1), (11, 0)])
def test_10_saniye_siniri(son_saniye, beklenen_alarm):
    olaylar = [olay(s, 1000 + s) for s in range(10)] + [olay(son_saniye, 2000)]

    assert len(tespit(olaylar)) == beklenen_alarm


def test_yavas_tarama_alarm_uretmez():
    # 2 saniyede bir yeni port: 10 saniyelik pencerede en fazla 6 port kalır.
    assert tespit([olay(2 * i, 1000 + i) for i in range(30)]) == []


def test_dusen_kayitta_port_icin_baska_deneme_kaldiysa_port_sayilmaya_devam_eder():
    # Port 100: t=0 ve t=5. Portlar 1..9: t=2..10. Port 200: t=11.
    # t=11'de port 100'ün t=0 kaydı düşer ama t=5 kaydı kalır -> 11 farklı port.
    # (Sadece set kullanılsaydı 100 silinir, 10 görünür ve alarm kaçardı.)
    olaylar = [olay(0, 100), olay(5, 100), olay(11, 200)]
    olaylar += [olay(2 + k, 1 + k) for k in range(9)]
    alarmlar = tespit(olaylar)

    assert len(alarmlar) == 1
    assert alarmlar[0]["farkli_port_sayisi"] == 11
    assert alarmlar[0]["ilk_gorulme"] == datetime(2026, 11, 21, 10, 0, 2)
    assert alarmlar[0]["tespit_zamani"] == datetime(2026, 11, 21, 10, 0, 11)


def test_devam_eden_tarama_icin_tekrar_alarm_uretilmez():
    alarmlar = tespit([olay(s, 1000 + s) for s in range(20)])

    assert len(alarmlar) == 1
    assert alarmlar[0]["tespit_zamani"] == datetime(2026, 11, 21, 10, 0, 10)


def test_ayri_iki_tarama_iki_alarm_uretir():
    olaylar = [olay(s, 1000 + s) for s in range(11)]
    olaylar += [olay(1000 + s, 1000 + s) for s in range(11)]
    alarmlar = tespit(olaylar)

    assert [a["tespit_zamani"] for a in alarmlar] == [
        datetime(2026, 11, 21, 10, 0, 10),
        datetime(2026, 11, 21, 10, 16, 50),
    ]


def test_ayni_saniyedeki_11_port_alarm_uretir():
    alarmlar = tespit([olay(0, 1000 + i) for i in range(11)])

    assert len(alarmlar) == 1
    assert alarmlar[0]["ilk_gorulme"] == alarmlar[0]["tespit_zamani"]


def test_zamani_olmayan_olay_atlanir():
    zamansiz = olay(10, 1010)
    zamansiz["zaman"] = None
    olaylar = [olay(s, 1000 + s) for s in range(10)] + [zamansiz]

    assert tespit(olaylar) == []


def test_ilgisiz_kayitlar_guvenle_atlanir():
    ssh_olayi = {"zaman": "Nov 21 10:00:00", "durum": "basarisiz", "yontem": "password", "kaynak_ip": KAYNAK_A}
    gurultu = [None, ssh_olayi, {}]
    alarmlar = tespit(gurultu + [olay(s, 1000 + s) for s in range(11)])

    assert len(alarmlar) == 1


def test_ornek_log_12_portluk_tarama_tek_alarm_uretir():
    kayitlar = read_log_lines(ORNEK_LOG)
    olaylar = [parse_nft_line(kayit["ham"]) for kayit in kayitlar]

    assert detect_port_scan(olaylar, yil=2026) == [{
        "kaynak_ip": "203.0.113.5",
        "hedef_ip": "10.0.0.2",
        "olay_turu": "port_scan",
        "farkli_port_sayisi": 11,
        "ilk_gorulme": datetime(2026, 11, 21, 10, 30, 1),
        "tespit_zamani": datetime(2026, 11, 21, 10, 30, 6),
    }]


def test_ornek_logda_ilk_10_port_alarm_vermez_11_port_verir():
    kayitlar = read_log_lines(ORNEK_LOG)
    olaylar = [parse_nft_line(kayit["ham"]) for kayit in kayitlar]
    tarama = [o for o in olaylar if o is not None and o["kaynak_ip"] == "203.0.113.5"]

    assert len(tarama) == 12
    assert detect_port_scan(tarama[:10], yil=2026) == []
    assert len(detect_port_scan(tarama[:11], yil=2026)) == 1
