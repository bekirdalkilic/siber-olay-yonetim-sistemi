import os

import psycopg
import pytest

from scripts import kullanici_olustur as ko
from src.api.kullanici import parola_dogru_mu

PAROLA = "cok-gizli-parola-987"


# ---------- saf fonksiyonlar ----------

@pytest.mark.parametrize("ad, beklenen", [
    ("yonetici1", True), ("ali.veli-2", True), ("abc", True), ("a" * 50, True),
    ("ab", False), ("a" * 51, False), ("", False), ("ali veli", False), ("ali@x", False),
    ("şeker", False), ("ali\n", False), ("ali'; DROP TABLE x;--", False),
])
def test_kullanici_adi_gecerli_mi(ad, beklenen):
    assert ko.kullanici_adi_gecerli_mi(ad) is beklenen


@pytest.mark.parametrize("parola, mesaj_var", [
    ("kisa", True),                  # 10 karakterden az
    ("p" * 257, True),               # çok uzun
    ("yonetici1", True),             # kısa (9)
    ("Yonetici123", False),          # uygun
    ("uzun-ve-uygun-parola", False),
    ("abc\x00defghijk", True),       # NUL karakteri
])
def test_parola_hatasi(parola, mesaj_var):
    assert (ko.parola_hatasi(parola, "baska") is not None) is mesaj_var


def test_parola_kullanici_adiyla_ayni_olamaz():
    assert ko.parola_hatasi("YoneticiKullanici", "yoneticikullanici") is not None


def test_parola_hashle_argon2id_ve_tuzlu():
    h1, h2 = ko.parola_hashle(PAROLA), ko.parola_hashle(PAROLA)
    assert h1.startswith("$argon2id$")   # migration'daki CHECK (parola_argon2id) ile uyumlu
    assert h1 != h2                      # her hash'e rastgele tuz eklenir
    assert parola_dogru_mu(h1, PAROLA) and not parola_dogru_mu(h1, PAROLA + "x")
    assert PAROLA not in h1


# ---------- main (veritabanı ve getpass sahte) ----------

class SahteImlec:
    def __init__(self, kullanici="postgres", insert_hatasi=None):
        self.kullanici = kullanici
        self.insert_hatasi = insert_hatasi
        self.sorgular = []
        self._son = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.sorgular.append((sql, params))
        if "current_user" in sql:
            self._son = (self.kullanici,)
        else:
            if self.insert_hatasi:
                raise self.insert_hatasi
            self._son = (7,)

    def fetchone(self):
        return self._son


class SahteBaglanti:
    def __init__(self, imlec):
        self.imlec = imlec

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return self.imlec


@pytest.fixture
def duzen(monkeypatch):
    """getpass ve veritabanı bağlantısını sahteler. Dönen nesne: istenen sahte davranışı ayarlar."""
    d = type("Duzen", (), {})()
    d.sorular = []
    d.yanitlar = [PAROLA, PAROLA]          # sırayla: parola, tekrar, (varsa) db parolası
    d.imlec = SahteImlec()
    d.baglantilar = []

    def sahte_getpass(istem=""):
        d.sorular.append(istem)
        return d.yanitlar.pop(0)

    def sahte_baglanti(url, db_parola=None):
        d.baglantilar.append((url, db_parola))
        return SahteBaglanti(d.imlec)

    monkeypatch.setattr("getpass.getpass", sahte_getpass)
    monkeypatch.setattr(ko, "yonetici_baglantisi", sahte_baglanti)
    return d


ORTAM = {"ADMIN_DATABASE_URL": "postgresql://postgres@localhost/siber_olay_yonetimi"}


def calistir(*argv, ortam=ORTAM):
    return ko.main(list(argv), ortam)


@pytest.mark.parametrize("yetki_adi, yetki_no", [("yonetici", 1), ("analist", 0)])
def test_hesap_olusturulur_ve_parola_hicbir_yere_yazilmaz(duzen, capsys, yetki_adi, yetki_no):
    kod = calistir("--kullanici-adi", "demo_kisi", "--yetki", yetki_adi)
    cikti = capsys.readouterr()

    assert kod == 0
    sql, params = duzen.imlec.sorgular[-1]
    assert "INSERT INTO kullanicilar" in sql and "%s" in sql   # parametreli sorgu
    adi, hash_, yetki = params
    assert (adi, yetki) == ("demo_kisi", yetki_no)
    assert hash_.startswith("$argon2id$") and parola_dogru_mu(hash_, PAROLA)
    assert PAROLA not in repr(duzen.imlec.sorgular)             # düz parola SQL'e hiç girmedi
    for metin in (cikti.out, cikti.err):
        assert PAROLA not in metin and hash_ not in metin       # ekrana da yazılmadı
    assert "id=7" in cikti.out
    assert len(duzen.sorular) == 2                              # getpass: parola + tekrar


def test_parolalar_uyusmazsa_baglanti_acilmaz(duzen, capsys):
    duzen.yanitlar = [PAROLA, PAROLA + "x"]
    assert calistir("--kullanici-adi", "demo_kisi", "--yetki", "analist") == 2
    assert duzen.baglantilar == []
    assert "farklı" in capsys.readouterr().err


def test_zayif_parola_reddedilir(duzen, capsys):
    duzen.yanitlar = ["kisa", "kisa"]
    assert calistir("--kullanici-adi", "demo_kisi", "--yetki", "analist") == 2
    assert duzen.baglantilar == []


def test_gecersiz_kullanici_adinda_parola_bile_sorulmaz(duzen):
    assert calistir("--kullanici-adi", "a b", "--yetki", "analist") == 2
    assert duzen.sorular == []


def test_admin_url_yoksa_hata(duzen, capsys):
    assert calistir("--kullanici-adi", "demo_kisi", "--yetki", "analist", ortam={}) == 2
    assert "ADMIN_DATABASE_URL" in capsys.readouterr().err
    assert duzen.sorular == []


def test_siber_api_ile_calismayi_reddeder(duzen, capsys):
    duzen.imlec = SahteImlec(kullanici="siber_api")
    assert calistir("--kullanici-adi", "demo_kisi", "--yetki", "analist") == 2
    assert not any("INSERT" in s for s, _ in duzen.imlec.sorgular)
    assert "siber_api" in capsys.readouterr().err


def test_var_olan_kullanici_ezilmez(duzen, capsys):
    duzen.imlec = SahteImlec(insert_hatasi=psycopg.errors.UniqueViolation("duplicate key"))
    assert calistir("--kullanici-adi", "demo_kisi", "--yetki", "analist") == 1
    cikti = capsys.readouterr()
    assert "zaten var" in cikti.err and PAROLA not in cikti.err + cikti.out


def test_veritabani_hatasi_metni_yazdirilmaz(duzen, capsys):
    gizli = "postgresql://postgres:COK-GIZLI-DB-PAROLASI@localhost/x"
    duzen.imlec = SahteImlec(insert_hatasi=psycopg.OperationalError(gizli))
    assert calistir("--kullanici-adi", "demo_kisi", "--yetki", "analist") == 1
    cikti = capsys.readouterr()
    assert "COK-GIZLI-DB-PAROLASI" not in cikti.err + cikti.out
    assert "OperationalError" in cikti.err


def test_db_parolasini_sor_getpass_ile_alinir_ve_url_ye_yazilmaz(duzen, capsys):
    duzen.yanitlar = [PAROLA, PAROLA, "DB-YONETICI-PAROLASI"]
    kod = calistir("--kullanici-adi", "demo_kisi", "--yetki", "yonetici", "--db-parolasini-sor")
    cikti = capsys.readouterr()
    assert kod == 0
    assert duzen.baglantilar == [(ORTAM["ADMIN_DATABASE_URL"], "DB-YONETICI-PAROLASI")]
    assert "DB-YONETICI-PAROLASI" not in cikti.out + cikti.err
    assert len(duzen.sorular) == 3


def test_db_parolasi_sorulmazsa_baglantiya_none_gider(duzen):
    calistir("--kullanici-adi", "demo_kisi", "--yetki", "yonetici")
    assert duzen.baglantilar == [(ORTAM["ADMIN_DATABASE_URL"], None)]


# ---------- gerçek SQL (sadece TEST_ADMIN_DATABASE_URL tanımlıysa) ----------

ADMIN_URL = os.environ.get("TEST_ADMIN_DATABASE_URL")


@pytest.mark.skipif(not ADMIN_URL, reason="TEST_ADMIN_DATABASE_URL tanımlı değil")
def test_db_gercek_hesap_olusturma_ve_tekrar_denemede_hata(monkeypatch, capsys):
    ad = "betik_%06d" % (os.getpid() % 1000000)
    monkeypatch.setattr("getpass.getpass", lambda istem="": PAROLA)
    ortam = {"ADMIN_DATABASE_URL": ADMIN_URL}
    assert ko.main(["--kullanici-adi", ad, "--yetki", "yonetici"], ortam) == 0
    with psycopg.connect(ADMIN_URL) as conn:
        hash_, yetki = conn.execute(
            "SELECT parola_hash, yetki FROM kullanicilar WHERE kullanici_adi = %s", (ad,)
        ).fetchone()
    assert yetki == 1 and parola_dogru_mu(hash_, PAROLA)
    # Aynı ad ikinci kez: hata, mevcut hash değişmez.
    assert ko.main(["--kullanici-adi", ad, "--yetki", "analist"], ortam) == 1
    with psycopg.connect(ADMIN_URL) as conn:
        assert conn.execute("SELECT parola_hash, yetki FROM kullanicilar WHERE kullanici_adi = %s",
                            (ad,)).fetchone() == (hash_, 1)
    assert PAROLA not in "".join(capsys.readouterr())
