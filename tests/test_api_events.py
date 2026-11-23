import json
import logging

import psycopg
import pytest

from src.api.app import create_app

ANAHTAR = "test-anahtari"
DB_ADRESI = "postgresql://kullanici:cok-gizli-sifre@localhost/test"


@pytest.fixture(autouse=True)
def sahte_db(monkeypatch):
    """Bu dosyadaki testler gerçek veritabanına bağlanmaz: olay_isle sahteyle değişir.

    Fixture, sahtenin aldığı çağrıların listesini döndürür: [(database_url, olay), ...]
    Sahte varsayılan olarak "yeni olay eklendi" der: (olay_id=1, tekrar_sayisi=1).
    """
    cagrilar = []

    def sahte(database_url, olay):
        cagrilar.append((database_url, olay))
        return (1, 1)

    monkeypatch.setattr("src.api.app.olay_isle", sahte)
    return cagrilar


@pytest.fixture
def istemci():
    app = create_app({"API_KEY": ANAHTAR, "DATABASE_URL": DB_ADRESI})
    return app.test_client()


def gecerli_olay(**degisiklik):
    olay = {
        "cihaz_adi": "fw-01",
        "olay_turu": "port_scan",
        "kaynak_ip": "203.0.113.5",
        "hedef_ip": "192.168.1.10",
        "olay_zamani": "2026-11-24T14:05:09+03:00",
    }
    olay.update(degisiklik)
    return olay


def gonder(istemci, govde, anahtar=ANAHTAR, **ekstra):
    """govde dict ise JSON'a çevirir; str ise olduğu gibi gönderir."""
    if not isinstance(govde, str):
        govde = json.dumps(govde)
    basliklar = {} if anahtar is None else {"X-API-KEY": anahtar}
    return istemci.post("/api/v1/events", data=govde, headers=basliklar, **ekstra)


# ---------- 401: anahtar ----------

def test_anahtar_yoksa_401(istemci):
    yanit = gonder(istemci, gecerli_olay(), anahtar=None)
    assert yanit.status_code == 401
    assert yanit.get_json()["hata"] == "gecersiz_api_anahtari"


@pytest.mark.parametrize("yanlis", [
    "yanlis", "test-anahtar", "test-anahtari ", "TEST-ANAHTARI", "",
])
def test_yanlis_anahtar_401(istemci, yanlis):
    assert gonder(istemci, gecerli_olay(), anahtar=yanlis).status_code == 401


def test_anahtar_govdeden_once_kontrol_edilir(istemci):
    # Gövde bozuk AMA anahtar da yok: 400 değil 401 görmeliyiz.
    assert gonder(istemci, "{bozuk", anahtar=None).status_code == 401


# ---------- 400: bozuk JSON ----------

@pytest.mark.parametrize("govde", ["{bozuk", "", "[1, 2", "tamamen metin", "[" * 5000])
def test_bozuk_json_400(istemci, govde):
    yanit = gonder(istemci, govde)
    assert yanit.status_code == 400
    assert yanit.get_json()["hata"] == "bozuk_json"


# ---------- 422: geçersiz veri ----------

@pytest.mark.parametrize("govde", ["[]", '"metin"', "123", "null"])
def test_json_nesne_degilse_422(istemci, govde):
    yanit = gonder(istemci, govde)
    assert yanit.status_code == 422
    assert "govde" in yanit.get_json()["alanlar"]


def test_bos_nesne_422_tum_alanlari_listeler(istemci):
    yanit = gonder(istemci, {})
    assert yanit.status_code == 422
    assert set(yanit.get_json()["alanlar"]) == {
        "cihaz_adi", "olay_turu", "kaynak_ip", "olay_zamani",
    }


@pytest.mark.parametrize("degisiklik, hatali_alan", [
    ({"olay_turu": "virus"}, "olay_turu"),
    ({"kaynak_ip": "999.1.1.1"}, "kaynak_ip"),
    ({"olay_zamani": "2026-11-24T14:05:09"}, "olay_zamani"),   # saat dilimi yok
    ({"hedef_ip": None}, "hedef_ip"),                          # port_scan'de zorunlu
])
def test_gecersiz_alan_422(istemci, degisiklik, hatali_alan):
    yanit = gonder(istemci, gecerli_olay(**degisiklik))
    assert yanit.status_code == 422
    assert hatali_alan in yanit.get_json()["alanlar"]


# ---------- 201 / 200 / 422: veritabanı sonuçları (DB sahte) ----------

def test_yeni_olay_201(istemci):
    yanit = gonder(istemci, gecerli_olay())
    assert yanit.status_code == 201
    assert yanit.get_json() == {"olay_id": 1, "tekrar_sayisi": 1, "yeni_olay": True}


def test_tekrar_eden_olay_200(istemci, monkeypatch):
    monkeypatch.setattr("src.api.app.olay_isle", lambda url, olay: (7, 3))
    yanit = gonder(istemci, gecerli_olay())
    assert yanit.status_code == 200
    assert yanit.get_json() == {"olay_id": 7, "tekrar_sayisi": 3, "yeni_olay": False}


def test_bilinmeyen_cihaz_422(istemci, monkeypatch):
    monkeypatch.setattr("src.api.app.olay_isle", lambda url, olay: None)
    yanit = gonder(istemci, gecerli_olay())
    assert yanit.status_code == 422
    assert yanit.get_json()["hata"] == "bilinmeyen_cihaz"
    assert "cihaz_adi" in yanit.get_json()["alanlar"]


def test_db_katmanina_dogru_veri_gider(istemci, sahte_db):
    gonder(istemci, gecerli_olay(cihaz_adi="  fw-01  "))
    (url, olay), = sahte_db
    assert url == DB_ADRESI                      # adres config'ten alınır
    assert olay["cihaz_adi"] == "fw-01"          # boşluklar kırpılmış
    assert olay["olay_zamani"].utcoffset() is not None   # saat dilimli datetime


def test_gecerli_ssh_hedef_ip_olmadan_201(istemci, sahte_db):
    olay = gecerli_olay(olay_turu="ssh_brute_force")
    del olay["hedef_ip"]
    assert gonder(istemci, olay).status_code == 201
    assert sahte_db[0][1]["hedef_ip"] is None


def test_content_type_text_plain_olsa_da_kabul(istemci):
    yanit = gonder(istemci, gecerli_olay(), content_type="text/plain")
    assert yanit.status_code == 201


def test_hatali_istekler_veritabanina_gitmez(istemci, sahte_db):
    gonder(istemci, gecerli_olay(), anahtar=None)   # 401
    gonder(istemci, "{bozuk")                       # 400
    gonder(istemci, {})                             # 422
    assert sahte_db == []


# ---------- 503 / 500: veritabanı hataları, gizli bilgi sızmaz ----------

SIR_METNI = f"connection to server failed: {DB_ADRESI} parola=cok-gizli-sifre"


@pytest.mark.parametrize("hata_sinifi, kod, ad", [
    (psycopg.OperationalError, 503, "veritabani_kullanilamiyor"),
    (psycopg.errors.DataError, 500, "veritabani_hatasi"),
    (psycopg.errors.ProgrammingError, 500, "veritabani_hatasi"),
])
def test_veritabani_hatalari_sir_sizdirmaz(istemci, monkeypatch, caplog, hata_sinifi, kod, ad):
    def bozuk(url, olay):
        raise hata_sinifi(SIR_METNI)

    monkeypatch.setattr("src.api.app.olay_isle", bozuk)
    with caplog.at_level(logging.DEBUG):
        yanit = gonder(istemci, gecerli_olay())
    assert yanit.status_code == kod
    assert yanit.get_json()["hata"] == ad
    for metin in (yanit.get_data(as_text=True), caplog.text):
        assert "cok-gizli-sifre" not in metin
        assert DB_ADRESI not in metin
        assert ANAHTAR not in metin
    assert hata_sinifi.__name__ in caplog.text   # sınıf adı loga yazılmış


def test_beklenmeyen_hata_500_json_sir_yok(istemci, monkeypatch):
    def bozuk(url, olay):
        raise RuntimeError(SIR_METNI)

    monkeypatch.setattr("src.api.app.olay_isle", bozuk)
    yanit = gonder(istemci, gecerli_olay())
    assert yanit.status_code == 500
    assert yanit.get_json()["hata"] == "internal_server_error"
    assert "cok-gizli-sifre" not in yanit.get_data(as_text=True)


# ---------- Flask'ın kendi hataları da JSON ----------

def test_get_ile_olay_adresi_405_json(istemci):
    yanit = istemci.get("/api/v1/events")
    assert yanit.status_code == 405
    assert yanit.get_json()["hata"] == "method_not_allowed"
    assert "POST" in yanit.headers["Allow"]


def test_bilinmeyen_adres_404_json(istemci):
    yanit = istemci.get("/yok")
    assert yanit.status_code == 404
    assert yanit.get_json()["hata"] == "not_found"


# ---------- Loglarda sır yok ----------

def test_loglarda_anahtar_ve_db_adresi_yok(istemci, caplog):
    with caplog.at_level(logging.DEBUG):
        gonder(istemci, gecerli_olay(), anahtar="yanlis-tahmin-123")
        gonder(istemci, gecerli_olay())            # doğru anahtar
    kayit = caplog.text
    assert "Reddedilen istek" in kayit             # uyarı gerçekten yazılmış
    assert "yanlis-tahmin-123" not in kayit
    assert ANAHTAR not in kayit
    assert "cok-gizli-sifre" not in kayit
    assert DB_ADRESI not in kayit
