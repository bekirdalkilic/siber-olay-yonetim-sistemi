import base64
import json
import logging
import re

import psycopg
import pytest

from src.api.app import create_app
from src.api.config import AyarHatasi, web_ayarlarini_oku

API_ANAHTARI = "test-api-anahtari"
DB_ADRESI = "postgresql://kullanici:cok-gizli-sifre@localhost/test"
SECRET_KEY = "x" * 40
GENEL_HATA = "Kullanıcı adı veya parola hatalı ya da hesap geçici olarak kilitli."

PAROLALAR = {"yonetici1": "yonetici-parolasi-1", "analist1": "analist-parolasi-1"}


@pytest.fixture
def kullanicilar(monkeypatch):
    """Sahte kullanıcı tablosu. Veritabanı katmanı (giris_isle / kullanici_getir) sahteyle değişir;
    Argon2 ve kilit mantığı test_kullanici.py'de ayrıca sınanır."""
    tablo = {
        1: {"id": 1, "kullanici_adi": "yonetici1", "yetki": 1},
        2: {"id": 2, "kullanici_adi": "analist1", "yetki": 0},
    }
    durum = type("Durum", (), {})()
    durum.tablo = tablo
    durum.giris_cagrilari = []

    def sahte_giris(database_url, kullanici_adi, parola):
        durum.giris_cagrilari.append((database_url, kullanici_adi, parola))
        for k in tablo.values():
            if k["kullanici_adi"] == kullanici_adi and PAROLALAR.get(kullanici_adi) == parola:
                return dict(k)
        return None

    monkeypatch.setattr("src.api.web.giris_isle", sahte_giris)
    monkeypatch.setattr("src.api.web.kullanici_getir",
                        lambda url, kimlik: dict(tablo[kimlik]) if kimlik in tablo else None)
    return durum


def uygulama_yap(**ekstra):
    ayar = {"API_KEY": API_ANAHTARI, "DATABASE_URL": DB_ADRESI, "SECRET_KEY": SECRET_KEY,
            "SESSION_COOKIE_SECURE": False}   # test istemcisi düz HTTP kullanır
    ayar.update(ekstra)
    return create_app(ayar)


@pytest.fixture
def istemci(kullanicilar):
    return uygulama_yap().test_client()


def csrf_al(istemci):
    govde = istemci.get("/giris").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([0-9a-f]{64})"', govde).group(1)


def giris_yap(istemci, kullanici_adi, parola, csrf="otomatik", **ekstra):
    if csrf == "otomatik":
        csrf = csrf_al(istemci)
    veri = {"kullanici_adi": kullanici_adi, "parola": parola}
    if csrf is not None:
        veri["csrf_token"] = csrf
    return istemci.post("/giris", data=veri, **ekstra)


def hata_kutusu(yanit):
    return re.search(r'<div class="alert alert-danger" role="alert">(.*?)</div>',
                     yanit.get_data(as_text=True), re.S).group(1)


# ---------- giriş sayfası ----------

def test_giris_sayfasi_formu_ve_yerel_bootstrap_i_icerir(istemci):
    yanit = istemci.get("/giris")
    govde = yanit.get_data(as_text=True)
    assert yanit.status_code == 200
    for parca in ('name="kullanici_adi"', 'name="parola"', 'type="password"', 'name="csrf_token"',
                  "/static/vendor/bootstrap/css/bootstrap.min.css"):
        assert parca in govde
    assert "cdn" not in govde.lower() and "http://" not in govde and "https://" not in govde


def test_yerel_bootstrap_dosyasi_sunulur(istemci):
    yanit = istemci.get("/static/vendor/bootstrap/css/bootstrap.min.css")
    assert yanit.status_code == 200 and yanit.mimetype == "text/css"


def test_ana_sayfa_girise_yonlendirir(istemci):
    yanit = istemci.get("/")
    assert yanit.status_code == 302 and yanit.headers["Location"].endswith("/giris")


def test_guvenlik_basliklari_var(istemci):
    h = istemci.get("/giris").headers
    assert "default-src 'self'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["Cache-Control"] == "no-store"


def test_oturum_cerezi_httponly_samesite_lax(istemci):
    cerez = istemci.get("/giris").headers["Set-Cookie"]
    assert "HttpOnly" in cerez and "SameSite=Lax" in cerez


def test_oturum_cerezi_varsayilan_olarak_secure():
    istemci = uygulama_yap(SESSION_COOKIE_SECURE=True).test_client()
    cerez = istemci.get("/giris", base_url="https://localhost").headers["Set-Cookie"]
    assert "Secure" in cerez


# ---------- CSRF ----------

@pytest.mark.parametrize("csrf", [None, "", "yanlis-token", "0" * 64])
def test_csrf_gecersizse_403_ve_giris_denenmez(istemci, kullanicilar, csrf):
    csrf_al(istemci)   # oturumda gerçek bir token olsun
    yanit = giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"], csrf=csrf)
    assert yanit.status_code == 403
    assert kullanicilar.giris_cagrilari == []


def test_oturumsuz_post_403(kullanicilar):
    yanit = uygulama_yap().test_client().post(
        "/giris", data={"kullanici_adi": "yonetici1", "parola": PAROLALAR["yonetici1"],
                        "csrf_token": "a" * 64})
    assert yanit.status_code == 403
    assert kullanicilar.giris_cagrilari == []


# ---------- yanlış giriş ----------

def test_yanlis_parola_401_genel_mesaj_parola_geri_yazilmaz(istemci):
    yanit = giris_yap(istemci, "yonetici1", "yanlis-parola-xyz")
    govde = yanit.get_data(as_text=True)
    assert yanit.status_code == 401
    assert hata_kutusu(yanit) == GENEL_HATA
    assert "yanlis-parola-xyz" not in govde
    assert 'value="yonetici1"' in govde          # kullanıcı adı forma geri doldurulur
    assert istemci.get("/yonetici").status_code == 302   # oturum açılmadı


def test_olmayan_kullanici_ile_yanlis_parola_ayni_mesaji_verir(istemci):
    a = giris_yap(istemci, "yonetici1", "yanlis")
    b = giris_yap(istemci, "hic_yok", "yanlis")
    assert a.status_code == b.status_code == 401
    assert hata_kutusu(a) == hata_kutusu(b) == GENEL_HATA


def test_kullanici_adi_sayfada_kacislanir(istemci):
    yanit = giris_yap(istemci, "<script>alert(1)</script>", "x")
    govde = yanit.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in govde
    assert "&lt;script&gt;" in govde


def test_kullanici_adi_bosluklari_kirpilir(istemci, kullanicilar):
    giris_yap(istemci, "  yonetici1  ", PAROLALAR["yonetici1"])
    assert kullanicilar.giris_cagrilari[-1][1] == "yonetici1"


# ---------- başarılı giriş ve yetki ----------

def test_yonetici_girisi_yonetici_sayfasina_gider(istemci):
    yanit = giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"])
    assert yanit.status_code == 302 and yanit.headers["Location"].endswith("/yonetici")
    sayfa = istemci.get("/yonetici")
    assert sayfa.status_code == 200
    govde = sayfa.get_data(as_text=True)
    assert "Yönetici paneli" in govde and "yonetici1" in govde and "Çıkış yap" in govde


def test_analist_girisi_analist_sayfasina_gider(istemci):
    yanit = giris_yap(istemci, "analist1", PAROLALAR["analist1"])
    assert yanit.status_code == 302 and yanit.headers["Location"].endswith("/analist")
    assert "Analist paneli" in istemci.get("/analist").get_data(as_text=True)


def test_analist_yonetici_sayfasini_acarsa_403(istemci):
    giris_yap(istemci, "analist1", PAROLALAR["analist1"])
    yanit = istemci.get("/yonetici")
    govde = yanit.get_data(as_text=True)
    assert yanit.status_code == 403
    assert "Erişim reddedildi" in govde
    assert "Yönetici paneli" not in govde and "Hoş geldiniz" not in govde


def test_yonetici_analist_sayfasini_da_acabilir(istemci):
    giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"])
    assert istemci.get("/analist").status_code == 200


@pytest.mark.parametrize("adres", ["/yonetici", "/analist"])
def test_girissiz_erisim_girise_yonlendirir(istemci, adres):
    yanit = istemci.get(adres)
    assert yanit.status_code == 302 and yanit.headers["Location"].endswith("/giris")


def test_yetki_dogrulugu_cerezden_degil_veritabanindan_gelir(istemci, kullanicilar):
    giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"])
    assert istemci.get("/yonetici").status_code == 200
    kullanicilar.tablo[1]["yetki"] = 0        # yönetici yetkisi sonradan alındı
    assert istemci.get("/yonetici").status_code == 403


def test_pasiflestirilen_kullanicinin_oturumu_gecersiz_olur(istemci, kullanicilar):
    giris_yap(istemci, "analist1", PAROLALAR["analist1"])
    del kullanicilar.tablo[2]                 # hesap pasifleştirildi/silindi
    yanit = istemci.get("/analist")
    assert yanit.status_code == 302 and yanit.headers["Location"].endswith("/giris")
    with istemci.session_transaction() as oturum:
        assert "kullanici_id" not in oturum   # oturum temizlendi


def test_next_parametresiyle_acik_yonlendirme_yok(istemci):
    yanit = giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"],
                      query_string={"next": "http://kotu-site.example/"})
    assert yanit.headers["Location"].endswith("/yonetici")
    assert "kotu-site" not in yanit.headers["Location"]


# ---------- oturum ----------

def test_oturumda_parola_yok_sadece_kimlik_ve_token(istemci):
    giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"])
    with istemci.session_transaction() as oturum:
        assert set(oturum) == {"kullanici_id", "csrf_token", "_permanent"}
        assert oturum["kullanici_id"] == 1 and oturum["_permanent"] is True
    cerez = istemci.get_cookie("session").value
    yuk = cerez.split(".")[0]
    cozulmus = base64.urlsafe_b64decode(yuk + "=" * (-len(yuk) % 4)) if not yuk.startswith(".") else b""
    assert PAROLALAR["yonetici1"].encode() not in cozulmus


def test_giris_sonrasi_csrf_token_yenilenir(istemci):
    once = csrf_al(istemci)
    giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"], csrf=once)
    govde = istemci.get("/yonetici").get_data(as_text=True)
    sonra = re.search(r'name="csrf_token" value="([0-9a-f]{64})"', govde).group(1)
    assert sonra != once


def test_oturum_30_dakikalik_kalici_cerez(istemci):
    giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"])
    cerez = [c for c in istemci.get("/yonetici").headers.getlist("Set-Cookie")][0]
    assert "Expires=" in cerez   # kalıcı oturum; süre PERMANENT_SESSION_LIFETIME


# ---------- çıkış ----------

def yonetici_csrf(istemci):
    govde = istemci.get("/yonetici").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([0-9a-f]{64})"', govde).group(1)


def test_cikis_oturumu_kapatir(istemci):
    giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"])
    yanit = istemci.post("/cikis", data={"csrf_token": yonetici_csrf(istemci)})
    assert yanit.status_code == 302 and yanit.headers["Location"].endswith("/giris")
    assert istemci.get("/yonetici").status_code == 302


def test_cikis_csrf_olmadan_403_ve_oturum_acik_kalir(istemci):
    giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"])
    assert istemci.post("/cikis", data={}).status_code == 403
    assert istemci.post("/cikis", data={"csrf_token": "yanlis"}).status_code == 403
    assert istemci.get("/yonetici").status_code == 200


def test_cikis_get_ile_yapilamaz(istemci):
    giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"])
    assert istemci.get("/cikis").status_code == 405
    assert istemci.get("/yonetici").status_code == 200


# ---------- veritabanı hataları ----------

SIR = f"connection failed {DB_ADRESI} cok-gizli-sifre"


def test_giriste_veritabani_hatasi_503_sir_yok(istemci, monkeypatch, caplog):
    def patlat(*a):
        raise psycopg.OperationalError(SIR)
    monkeypatch.setattr("src.api.web.giris_isle", patlat)
    csrf = csrf_al(istemci)
    with caplog.at_level(logging.DEBUG):
        yanit = giris_yap(istemci, "yonetici1", "parola", csrf=csrf)
    assert yanit.status_code == 503
    for metin in (yanit.get_data(as_text=True), caplog.text):
        assert "cok-gizli-sifre" not in metin and DB_ADRESI not in metin
    assert "OperationalError" in caplog.text


def test_korumali_sayfada_veritabani_hatasi_503(istemci, monkeypatch):
    giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"])
    def patlat(*a):
        raise psycopg.errors.DataError(SIR)
    monkeypatch.setattr("src.api.web.kullanici_getir", patlat)
    yanit = istemci.get("/yonetici")
    assert yanit.status_code == 503 and "cok-gizli-sifre" not in yanit.get_data(as_text=True)


# ---------- ayarlar ve mevcut API ----------

def test_secret_key_yoksa_web_arayuzu_kapali_api_calisir(kullanicilar):
    app = create_app({"API_KEY": API_ANAHTARI, "DATABASE_URL": DB_ADRESI})
    istemci = app.test_client()
    assert "web" not in app.blueprints
    assert istemci.get("/giris").status_code == 404
    assert istemci.get("/health").status_code == 200
    assert istemci.post("/api/v1/events", data="{}").status_code == 401   # API anahtarı hâlâ şart


def test_olay_api_si_web_arayuzu_acikken_de_ayni_calisir(istemci):
    yanit = istemci.post("/api/v1/events", data="{}", headers={"X-API-KEY": API_ANAHTARI})
    assert yanit.status_code == 422
    # Web oturumu API'nin anahtar kontrolünü atlatmaz:
    giris_yap(istemci, "yonetici1", PAROLALAR["yonetici1"])
    assert istemci.post("/api/v1/events", data="{}").status_code == 401


def test_ortamdan_baslatilirken_secret_key_okunur(monkeypatch):
    monkeypatch.setenv("API_KEY", API_ANAHTARI)
    monkeypatch.setenv("DATABASE_URL", DB_ADRESI)
    monkeypatch.setenv("SECRET_KEY", SECRET_KEY)
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    app = create_app()
    assert "web" in app.blueprints
    assert app.config["SESSION_COOKIE_SECURE"] is True and app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_ortamdan_baslatilirken_secret_key_yoksa_uyari(monkeypatch, caplog):
    monkeypatch.setenv("API_KEY", API_ANAHTARI)
    monkeypatch.setenv("DATABASE_URL", DB_ADRESI)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with caplog.at_level(logging.WARNING):
        app = create_app()
    assert "web" not in app.blueprints
    assert "SECRET_KEY tanımlı değil" in caplog.text


# ---------- web_ayarlarini_oku ----------

def test_web_ayarlari_varsayilanlar():
    assert web_ayarlarini_oku({}) == {"SESSION_COOKIE_SECURE": True}


def test_web_ayarlari_anahtar_okunur():
    ayar = web_ayarlarini_oku({"SECRET_KEY": SECRET_KEY})
    assert ayar == {"SESSION_COOKIE_SECURE": True, "SECRET_KEY": SECRET_KEY}


def test_web_ayarlari_kisa_anahtar_hata_verir_degeri_yazmaz():
    with pytest.raises(AyarHatasi) as hata:
        web_ayarlarini_oku({"SECRET_KEY": "kisa-ama-gizli"})
    assert "kisa-ama-gizli" not in str(hata.value) and "SECRET_KEY" in str(hata.value)


@pytest.mark.parametrize("deger, beklenen", [("0", False), ("false", False), ("FALSE", False),
                                            ("1", True), ("evet", True)])
def test_web_ayarlari_cookie_secure(deger, beklenen):
    assert web_ayarlarini_oku({"COOKIE_SECURE": deger})["SESSION_COOKIE_SECURE"] is beklenen
