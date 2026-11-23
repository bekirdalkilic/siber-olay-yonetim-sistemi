from datetime import datetime, timedelta, timezone

import pytest

from src.api.validation import iso_zaman_coz, ip_coz, olay_dogrula


# ---------- ip_coz ----------

@pytest.mark.parametrize("deger, beklenen", [
    ("192.168.1.10", "192.168.1.10"),
    ("::1", "::1"),
    ("2001:DB8::1", "2001:db8::1"),   # IPv6 küçük harfli standart biçime çevrilir
])
def test_ip_coz_gecerli(deger, beklenen):
    assert ip_coz(deger) == beklenen


@pytest.mark.parametrize("deger", [
    "10.0.0.0/8", "fe80::1%eth0", "999.1.1.1", "1.2.3", "", " 1.2.3.4",
    "abc", 123, None, ["1.2.3.4"],
])
def test_ip_coz_gecersiz(deger):
    assert ip_coz(deger) is None


# ---------- iso_zaman_coz ----------

def test_iso_zaman_offset_korunur():
    z = iso_zaman_coz("2026-11-24T14:05:09+03:00")
    assert z.utcoffset() == timedelta(hours=3)
    assert z == datetime(2026, 11, 24, 11, 5, 9, tzinfo=timezone.utc)


def test_iso_zaman_z_harfi_utc_demek():
    assert iso_zaman_coz("2026-11-24T11:05:09Z") == iso_zaman_coz("2026-11-24T14:05:09+03:00")


@pytest.mark.parametrize("metin", [
    "2026-11-24T14:05:09.123+03:00",
    "2026-11-24T14:05:09.123456Z",
])
def test_iso_zaman_kesirli_saniye(metin):
    assert iso_zaman_coz(metin) is not None


@pytest.mark.parametrize("metin", [
    "2026-11-24T14:05:09",            # saat dilimi yok
    "2026-11-24",                     # sadece tarih
    "2026-11-24 14:05:09+03:00",      # T yerine boşluk
    "2026-13-24T14:05:09+03:00",      # 13. ay
    "2026-11-24T14:05:09+99:99",      # saçma offset
    "2026-11-24T14:05:09+03:00\n",    # sondaki artık
    "0001-01-01T00:00:00+03:00",      # UTC'ye çevrilemeyen uç tarih (alt taşma)
    "9999-12-31T23:59:59-03:00",      # UTC'ye çevrilemeyen uç tarih (üst taşma)
    1700000000, None,
])
def test_iso_zaman_gecersiz(metin):
    assert iso_zaman_coz(metin) is None


# ---------- olay_dogrula ----------

def gecerli(**degisiklik):
    olay = {
        "cihaz_adi": "fw-01",
        "olay_turu": "port_scan",
        "kaynak_ip": "203.0.113.5",
        "hedef_ip": "192.168.1.10",
        "olay_zamani": "2026-11-24T14:05:09+03:00",
    }
    olay.update(degisiklik)
    return olay


def test_gecerli_port_scan():
    temiz, hatalar = olay_dogrula(gecerli())
    assert hatalar == {}
    assert temiz["olay_turu"] == "port_scan"
    assert temiz["hedef_ip"] == "192.168.1.10"
    # ilk_gorulme verilmediyse olay_zamani'na eşit olur
    assert temiz["ilk_gorulme"] == temiz["olay_zamani"]


def test_gecerli_ssh_hedef_ip_olmadan():
    olay = gecerli(olay_turu="ssh_brute_force")
    del olay["hedef_ip"]
    temiz, hatalar = olay_dogrula(olay)
    assert hatalar == {}
    assert temiz["hedef_ip"] is None


def test_ssh_hedef_ip_null_olabilir():
    temiz, hatalar = olay_dogrula(gecerli(olay_turu="ssh_brute_force", hedef_ip=None))
    assert hatalar == {}


def test_port_scan_hedef_ip_olmadan_hata():
    olay = gecerli()
    del olay["hedef_ip"]
    temiz, hatalar = olay_dogrula(olay)
    assert temiz is None
    assert list(hatalar) == ["hedef_ip"]


def test_port_scan_hedef_ip_null_hata():
    _, hatalar = olay_dogrula(gecerli(hedef_ip=None))
    assert "hedef_ip" in hatalar


def test_ssh_ama_hedef_ip_bozuksa_hata():
    _, hatalar = olay_dogrula(gecerli(olay_turu="ssh_brute_force", hedef_ip="bozuk"))
    assert "hedef_ip" in hatalar


def test_ilk_gorulme_olay_zamanindan_sonra_olamaz():
    _, hatalar = olay_dogrula(gecerli(ilk_gorulme="2026-11-24T14:05:10+03:00"))
    assert "ilk_gorulme" in hatalar


def test_ilk_gorulme_once_veya_esit_olabilir():
    temiz, hatalar = olay_dogrula(gecerli(ilk_gorulme="2026-11-24T14:05:00+03:00"))
    assert hatalar == {}
    assert temiz["ilk_gorulme"] < temiz["olay_zamani"]
    _, hatalar = olay_dogrula(gecerli(ilk_gorulme="2026-11-24T14:05:09+03:00"))
    assert hatalar == {}


def test_ilk_gorulme_saat_dilimsiz_hata():
    _, hatalar = olay_dogrula(gecerli(ilk_gorulme="2026-11-24T14:05:00"))
    assert "ilk_gorulme" in hatalar


@pytest.mark.parametrize("ad", ["", "   ", None, 5])
def test_cihaz_adi_bos_veya_metin_degil(ad):
    _, hatalar = olay_dogrula(gecerli(cihaz_adi=ad))
    assert "cihaz_adi" in hatalar


def test_cihaz_adi_bosluklari_kirpilir():
    temiz, _ = olay_dogrula(gecerli(cihaz_adi="  fw-01  "))
    assert temiz["cihaz_adi"] == "fw-01"


def test_bilinmeyen_olay_turu():
    _, hatalar = olay_dogrula(gecerli(olay_turu="virus"))
    assert "olay_turu" in hatalar


@pytest.mark.parametrize("govde", [[], "metin", 123, None])
def test_govde_nesne_degilse_hata(govde):
    temiz, hatalar = olay_dogrula(govde)
    assert temiz is None
    assert list(hatalar) == ["govde"]


def test_tum_hatalar_birlikte_toplanir():
    temiz, hatalar = olay_dogrula({})
    assert temiz is None
    assert set(hatalar) == {"cihaz_adi", "olay_turu", "kaynak_ip", "olay_zamani"}


def test_fazladan_alanlar_yok_sayilir():
    temiz, hatalar = olay_dogrula(gecerli(rastgele="x"))
    assert hatalar == {}
    assert "rastgele" not in temiz
