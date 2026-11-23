import hashlib
import os
import random
import re

import psycopg
import pytest

from src.api.db import olay_isle, parmak_izi_uret
from src.api.validation import iso_zaman_coz, olay_dogrula

# ---------- parmak_izi_uret (veritabanı gerekmez) ----------

ZAMAN = iso_zaman_coz("2026-11-24T14:05:09+03:00")


def pi(**degisiklik):
    arg = dict(
        cihaz_id=7, olay_turu="port_scan", kaynak_ip="203.0.113.5",
        hedef_ip="192.168.1.10", olay_zamani=ZAMAN,
    )
    arg.update(degisiklik)
    return parmak_izi_uret(**arg)


def test_parmak_izi_sema_formatina_uyar():
    # database/schema.sql: CHECK (fingerprint ~ '^[0-9a-f]{64}$')
    assert re.fullmatch(r"[0-9a-f]{64}", pi())


def test_parmak_izi_bilinen_degerle_ayni():
    # Biçimi sabitler: cihaz_id|olay_turu|kaynak_ip|hedef_ip|UTC günü
    beklenen = hashlib.sha256(b"7|port_scan|203.0.113.5|192.168.1.10|2026-11-24").hexdigest()
    assert pi() == beklenen


def test_parmak_izi_hedef_yoksa_bos_metin_katilir():
    beklenen = hashlib.sha256(b"7|ssh_brute_force|203.0.113.5||2026-11-24").hexdigest()
    assert pi(olay_turu="ssh_brute_force", hedef_ip=None) == beklenen


@pytest.mark.parametrize("degisiklik", [
    {"cihaz_id": 8},
    {"olay_turu": "ssh_brute_force"},
    {"kaynak_ip": "203.0.113.6"},
    {"hedef_ip": "192.168.1.11"},
    {"hedef_ip": None},
    {"olay_zamani": iso_zaman_coz("2026-11-25T14:05:09+03:00")},
])
def test_parmak_izi_her_bilesen_sonucu_degistirir(degisiklik):
    assert pi(**degisiklik) != pi()


def test_parmak_izi_gun_utc_uzerinden_hesaplanir():
    # İkisi de 23 Kasım 22:00-22:30 UTC; yerel tarihleri farklı (24 / 23 Kasım).
    a = iso_zaman_coz("2026-11-24T01:00:00+03:00")
    b = iso_zaman_coz("2026-11-23T22:30:00Z")
    assert pi(olay_zamani=a) == pi(olay_zamani=b)


def test_parmak_izi_utc_gece_yarisinda_gun_degisir():
    once = iso_zaman_coz("2026-11-23T23:59:59Z")
    sonra = iso_zaman_coz("2026-11-24T00:00:00Z")
    assert pi(olay_zamani=once) != pi(olay_zamani=sonra)


# ---------- bağlantı hatası (veritabanı gerekmez) ----------

def test_baglanti_kurulamazsa_psycopg_operationalerror_firlar():
    olay, _ = olay_dogrula({
        "cihaz_adi": "x", "olay_turu": "port_scan", "kaynak_ip": "10.0.0.1",
        "hedef_ip": "10.0.0.2", "olay_zamani": "2026-11-24T10:00:00Z",
    })
    # 127.0.0.1:1 -> hiçbir şey dinlemiyor
    with pytest.raises(psycopg.OperationalError):
        olay_isle("postgresql://u@127.0.0.1:1/x", olay)


# ---------- gerçek SQL testleri: sadece TEST_DATABASE_URL tanımlıysa ----------
# Bu testler AYRI bir test veritabanında çalışmalıdır (içinde "test-fw-01"
# cihazı olan, schema.sql uygulanmış). Gerçek veritabanında ÇALIŞTIRMAYIN:
# siber_api satır silemediği için test satırları orada kalır.

TEST_URL = os.environ.get("TEST_DATABASE_URL")
veritabani_gerekli = pytest.mark.skipif(
    not TEST_URL, reason="TEST_DATABASE_URL tanımlı değil (gerçek SQL testleri atlandı)"
)
TEST_CIHAZ = "test-fw-01"


def rastgele_ip():
    # Her çalıştırmada farklı IP: eski çalıştırmaların satırlarıyla çakışmasın.
    return "10.{}.{}.{}".format(*(random.randint(1, 254) for _ in range(3)))


def olay(zaman="2026-11-24T12:00:00Z", **degisiklik):
    veri = {
        "cihaz_adi": TEST_CIHAZ, "olay_turu": "port_scan", "kaynak_ip": rastgele_ip(),
        "hedef_ip": "192.0.2.50", "olay_zamani": zaman,
    }
    veri.update(degisiklik)
    temiz, hatalar = olay_dogrula(veri)
    assert hatalar == {}
    return temiz


def satir_oku(olay_id):
    with psycopg.connect(TEST_URL) as conn:
        return conn.execute(
            "SELECT cihaz_id, host(kaynak_ip), host(hedef_ip), olay_turu, fingerprint,"
            " tekrar_sayisi, ilk_gorulme, son_gorulme, olay_zamani"
            " FROM olaylar WHERE id = %s", (olay_id,)
        ).fetchone()


@veritabani_gerekli
def test_yeni_olay_eklenir():
    o = olay()
    olay_id, tekrar = olay_isle(TEST_URL, o)
    assert tekrar == 1
    (cihaz_id, kaynak, hedef, tur, parmak, sayi, ilk, son, zaman) = satir_oku(olay_id)
    assert (kaynak, hedef, tur, sayi) == (o["kaynak_ip"], "192.0.2.50", "port_scan", 1)
    assert re.fullmatch(r"[0-9a-f]{64}", parmak)
    assert parmak == parmak_izi_uret(cihaz_id, tur, kaynak, hedef, o["olay_zamani"])
    assert ilk == son == zaman == o["olay_zamani"]


@veritabani_gerekli
def test_ayni_olay_tekrar_gelirse_satir_acilmaz_sayac_artar():
    o = olay()
    id1, t1 = olay_isle(TEST_URL, o)
    id2, t2 = olay_isle(TEST_URL, o)
    id3, t3 = olay_isle(TEST_URL, o)
    assert id1 == id2 == id3
    assert (t1, t2, t3) == (1, 2, 3)
    # Bilinen sınırlama: AYNI istek tekrar gönderilirse de sayaç artar (idempotency yok).


@veritabani_gerekli
def test_ilk_gorulme_en_erken_son_gorulme_en_gec_korunur():
    ip = rastgele_ip()
    olay_id, _ = olay_isle(TEST_URL, olay("2026-11-24T12:00:00Z", kaynak_ip=ip))
    # Daha geç bir tekrar: son_gorulme ilerler, ilk_gorulme aynı kalır.
    olay_isle(TEST_URL, olay("2026-11-24T12:30:00Z", kaynak_ip=ip))
    s = satir_oku(olay_id)
    assert s[6].isoformat().startswith("2026-11-24T12:00:00")
    assert s[7].isoformat().startswith("2026-11-24T12:30:00")
    # Gecikmiş (daha eski) bir bildirim: ilk_gorulme geriye gider, son_gorulme düşmez.
    olay_isle(TEST_URL, olay("2026-11-24T11:00:00Z", ilk_gorulme="2026-11-24T10:00:00Z",
                             kaynak_ip=ip))
    s = satir_oku(olay_id)
    assert s[5] == 3
    assert s[6].isoformat().startswith("2026-11-24T10:00:00")
    assert s[7].isoformat().startswith("2026-11-24T12:30:00")
    # olay_zamani (satırı oluşturan ilk alarm) değişmez.
    assert s[8].isoformat().startswith("2026-11-24T12:00:00")


@veritabani_gerekli
def test_ayni_utc_gunu_farkli_saat_dilimiyle_ayni_satir():
    ip = rastgele_ip()
    id1, _ = olay_isle(TEST_URL, olay("2026-11-24T01:00:00+03:00", kaynak_ip=ip))
    id2, t2 = olay_isle(TEST_URL, olay("2026-11-23T22:30:00Z", kaynak_ip=ip))
    assert id1 == id2 and t2 == 2


@veritabani_gerekli
def test_ertesi_utc_gunu_yeni_satir():
    ip = rastgele_ip()
    id1, _ = olay_isle(TEST_URL, olay("2026-11-24T23:59:00Z", kaynak_ip=ip))
    id2, t2 = olay_isle(TEST_URL, olay("2026-11-25T00:01:00Z", kaynak_ip=ip))
    assert id1 != id2 and t2 == 1


@veritabani_gerekli
def test_farkli_hedef_ip_ayri_satir():
    ip = rastgele_ip()
    id1, _ = olay_isle(TEST_URL, olay(kaynak_ip=ip, hedef_ip="192.0.2.50"))
    id2, _ = olay_isle(TEST_URL, olay(kaynak_ip=ip, hedef_ip="192.0.2.51"))
    assert id1 != id2


@veritabani_gerekli
def test_ssh_olayi_hedef_ip_olmadan_kaydedilir_ve_tekillesir():
    ip = rastgele_ip()
    o = olay(olay_turu="ssh_brute_force", kaynak_ip=ip, hedef_ip=None)
    id1, t1 = olay_isle(TEST_URL, o)
    id2, t2 = olay_isle(TEST_URL, o)
    assert id1 == id2 and (t1, t2) == (1, 2)
    assert satir_oku(id1)[2] is None   # hedef_ip NULL


@veritabani_gerekli
def test_bilinmeyen_cihaz_none_doner_ve_satir_eklenmez():
    ip = rastgele_ip()
    assert olay_isle(TEST_URL, olay(cihaz_adi="yok-boyle-cihaz", kaynak_ip=ip)) is None
    with psycopg.connect(TEST_URL) as conn:
        assert conn.execute(
            "SELECT count(*) FROM olaylar WHERE kaynak_ip = %s", (ip,)
        ).fetchone()[0] == 0
