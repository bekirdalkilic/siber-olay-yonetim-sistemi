import os
import random
from datetime import datetime, timedelta, timezone

import psycopg
import pytest
from argon2 import PasswordHasher

from src.api import kullanici as k
from src.api.kullanici import (
    HATALI_GIRIS_ESIGI,
    KILIT_SURESI,
    girdi_gecerli_mi,
    giris_dene,
    giris_isle,
    giris_sonucu_hesapla,
    kullanici_getir,
    parola_dogru_mu,
)

# Testlerde hızlı (ucuz parametreli) bir Argon2id kullanılır; doğrulama hash'in içindeki
# ayarları okuduğu için üretimdeki varsayılan ayarlı doğrulayıcı bunu yine doğrular.
HIZLI = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
PAROLA = "dogru-parola-123"
HASH = HIZLI.hash(PAROLA)
SIMDI = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)


# ---------- parola_dogru_mu ----------

def test_hash_argon2id_biciminde():
    assert HASH.startswith("$argon2id$")   # migration'daki CHECK (parola_argon2id) ile uyumlu


def test_dogru_parola_kabul_edilir():
    assert parola_dogru_mu(HASH, PAROLA) is True


@pytest.mark.parametrize("deneme", ["yanlis-parola", "", "DOGRU-PAROLA-123", PAROLA + " "])
def test_yanlis_parola_reddedilir(deneme):
    assert parola_dogru_mu(HASH, deneme) is False


@pytest.mark.parametrize("bozuk_hash", ["", "duz-metin", "$argon2id$bozuk", "$2b$12$baskaalgoritma"])
def test_bozuk_hash_cokertmez_false_doner(bozuk_hash):
    assert parola_dogru_mu(bozuk_hash, PAROLA) is False


# ---------- girdi_gecerli_mi ----------

@pytest.mark.parametrize("ad, parola, beklenen", [
    ("yonetici1", "parola", True),
    ("", "parola", False),
    ("yonetici1", "", False),
    ("a" * 50, "p", True),
    ("a" * 51, "p", False),
    ("ad", "p" * 256, True),
    ("ad", "p" * 257, False),
    ("ad\x00", "parola", False),
    ("ad", "pa\x00rola", False),
    (None, "parola", False),
    ("ad", None, False),
    (123, "parola", False),
])
def test_girdi_gecerli_mi(ad, parola, beklenen):
    assert girdi_gecerli_mi(ad, parola) is beklenen


# ---------- giris_sonucu_hesapla (saf fonksiyon: kilit kuralının kendisi) ----------

def sonuc(hatali=0, kilit=None, aktif=True, dogru=False, simdi=SIMDI):
    return giris_sonucu_hesapla(hatali, kilit, aktif, dogru, simdi)


def test_dogru_parola_giris_basarili_sayac_sifirlanir():
    assert sonuc(hatali=3, dogru=True) == (True, 0, None)


def test_yanlis_parola_sayaci_artirir_kilit_yok():
    assert sonuc(hatali=0) == (False, 1, None)
    assert sonuc(hatali=3) == (False, 4, None)


def test_dorduncu_hatadan_sonra_dogru_parola_hala_girer():
    assert sonuc(hatali=4, dogru=True)[0] is True


def test_besinci_hatali_giris_15_dakika_kilitler():
    assert HATALI_GIRIS_ESIGI == 5 and KILIT_SURESI == timedelta(minutes=15)
    assert sonuc(hatali=4) == (False, 5, SIMDI + timedelta(minutes=15))


def test_kilitliyken_dogru_parola_bile_reddedilir_ve_kilit_uzamaz():
    kilit = SIMDI + timedelta(minutes=10)
    assert sonuc(hatali=5, kilit=kilit, dogru=True) == (False, 5, kilit)
    assert sonuc(hatali=5, kilit=kilit, dogru=False) == (False, 5, kilit)   # yanlış da kilidi uzatmaz


def test_kilit_tam_bitis_aninda_acilir():
    assert sonuc(hatali=5, kilit=SIMDI, dogru=True)[0] is True
    bir_saniye_once = SIMDI + timedelta(seconds=1)
    assert sonuc(hatali=5, kilit=bir_saniye_once, dogru=True)[0] is False


def test_kilit_bittikten_sonra_dogru_parola_girer_ve_temizler():
    eski_kilit = SIMDI - timedelta(minutes=1)
    assert sonuc(hatali=5, kilit=eski_kilit, dogru=True) == (True, 0, None)


def test_kilit_bittikten_sonra_yanlis_parola_yeni_diziyi_baslatir():
    eski_kilit = SIMDI - timedelta(minutes=1)
    # Sayaç 5'ten 6'ya değil, 1'e döner; hemen yeniden kilitlenmez.
    assert sonuc(hatali=5, kilit=eski_kilit, dogru=False) == (False, 1, None)


def test_pasif_hesap_dogru_parolayla_bile_giremez_sayac_degismez():
    assert sonuc(hatali=2, aktif=False, dogru=True) == (False, 2, None)


# ---------- giris_dene (SQL yapıştırıcısı; cursor sahte) ----------

class SahteImlec:
    """Gerçek cursor yerine geçer: SELECT'e hazır satırı verir, UPDATE'leri kaydeder."""

    def __init__(self, satir):
        self.satir = satir
        self.guncellemeler = []

    def execute(self, sql, params=None):
        if sql.lstrip().startswith("UPDATE"):
            self.guncellemeler.append(params)

    def fetchone(self):
        return self.satir


def satir(hatali=0, kilit=None, aktif=True, yetki=1):
    return (7, "yonetici1", HASH, yetki, aktif, hatali, kilit)


def test_giris_basarili_kullanici_sozlugu_doner():
    imlec = SahteImlec(satir(yetki=1))
    assert giris_dene(imlec, "yonetici1", PAROLA, SIMDI) == {
        "id": 7, "kullanici_adi": "yonetici1", "yetki": 1,
    }
    assert imlec.guncellemeler == []   # sayaç zaten 0: gereksiz UPDATE yok


def test_basarili_giris_eski_sayaci_sifirlar():
    imlec = SahteImlec(satir(hatali=3))
    assert giris_dene(imlec, "yonetici1", PAROLA, SIMDI) is not None
    assert imlec.guncellemeler == [(0, None, 7)]


def test_yanlis_parola_none_doner_sayaci_kaydeder():
    imlec = SahteImlec(satir(hatali=1))
    assert giris_dene(imlec, "yonetici1", "yanlis", SIMDI) is None
    assert imlec.guncellemeler == [(2, None, 7)]


def test_besinci_yanlis_kilidi_kaydeder():
    imlec = SahteImlec(satir(hatali=4))
    assert giris_dene(imlec, "yonetici1", "yanlis", SIMDI) is None
    assert imlec.guncellemeler == [(5, SIMDI + timedelta(minutes=15), 7)]


def test_kilitliyken_dogru_parola_none_ve_guncelleme_yok():
    imlec = SahteImlec(satir(hatali=5, kilit=SIMDI + timedelta(minutes=5)))
    assert giris_dene(imlec, "yonetici1", PAROLA, SIMDI) is None
    assert imlec.guncellemeler == []


def test_kullanici_yoksa_none_doner_ama_yine_de_hash_dogrulamasi_calisir(monkeypatch):
    cagrilar = []
    gercek = k.parola_dogru_mu
    monkeypatch.setattr(k, "parola_dogru_mu", lambda h, p: (cagrilar.append(h), gercek(h, p))[1])
    imlec = SahteImlec(None)
    assert giris_dene(imlec, "yok", "herhangi", SIMDI) is None
    assert cagrilar == [k._SAHTE_HASH]   # süre farkı "kullanıcı var mı" bilgisini sızdırmasın
    assert imlec.guncellemeler == []


def test_kilitli_hesapta_da_hash_dogrulamasi_calisir(monkeypatch):
    cagrilar = []
    gercek = k.parola_dogru_mu
    monkeypatch.setattr(k, "parola_dogru_mu", lambda h, p: (cagrilar.append(h), gercek(h, p))[1])
    giris_dene(SahteImlec(satir(hatali=5, kilit=SIMDI + timedelta(minutes=5))), "yonetici1", "x", SIMDI)
    assert cagrilar == [HASH]


def test_giris_isle_gecersiz_girdide_veritabanina_gitmez(monkeypatch):
    def patlat(*a, **kw):
        raise AssertionError("bağlantı açılmamalıydı")
    monkeypatch.setattr(k.psycopg, "connect", patlat)
    assert giris_isle("postgresql://x", "ad\x00", "parola") is None
    assert giris_isle("postgresql://x", "", "parola") is None
    assert giris_isle("postgresql://x", "ad", "p" * 300) is None


# ---------- gerçek SQL testleri: TEST_DATABASE_URL (siber_api) + TEST_ADMIN_DATABASE_URL ----------
# Bunlar AYRI bir test veritabanında çalışmalıdır (schema.sql + 001_kullanicilar.sql uygulanmış).
# Gerçek veritabanında ÇALIŞTIRMAYIN: test kullanıcıları orada kalır.

API_URL = os.environ.get("TEST_DATABASE_URL")
ADMIN_URL = os.environ.get("TEST_ADMIN_DATABASE_URL")
veritabani_gerekli = pytest.mark.skipif(
    not (API_URL and ADMIN_URL),
    reason="TEST_DATABASE_URL ve TEST_ADMIN_DATABASE_URL tanımlı değil (gerçek SQL testleri atlandı)",
)


def yeni_kullanici(yetki=0, aktif=True):
    ad = "test_%06d" % random.randint(0, 999999)
    with psycopg.connect(ADMIN_URL) as conn:
        kimlik = conn.execute(
            "INSERT INTO kullanicilar (kullanici_adi, parola_hash, yetki, aktif_mi)"
            " VALUES (%s, %s, %s, %s) RETURNING id", (ad, HASH, yetki, aktif)
        ).fetchone()[0]
    return kimlik, ad


def sayac_oku(kimlik):
    with psycopg.connect(ADMIN_URL) as conn:
        return conn.execute(
            "SELECT hatali_giris, kilit_bitis FROM kullanicilar WHERE id = %s", (kimlik,)
        ).fetchone()


@veritabani_gerekli
def test_db_basarili_giris():
    kimlik, ad = yeni_kullanici(yetki=1)
    assert giris_isle(API_URL, ad, PAROLA, SIMDI) == {"id": kimlik, "kullanici_adi": ad, "yetki": 1}


@veritabani_gerekli
def test_db_yanlis_parola_sayaci_kalici_artirir():
    kimlik, ad = yeni_kullanici()
    for beklenen in (1, 2, 3):
        assert giris_isle(API_URL, ad, "yanlis", SIMDI) is None
        assert sayac_oku(kimlik)[0] == beklenen   # transaction COMMIT edilmiş olmalı


@veritabani_gerekli
def test_db_bes_hatadan_sonra_kilit_ve_kilit_bitince_giris():
    kimlik, ad = yeni_kullanici()
    for _ in range(5):
        giris_isle(API_URL, ad, "yanlis", SIMDI)
    sayi, kilit = sayac_oku(kimlik)
    assert sayi == 5 and kilit == SIMDI + timedelta(minutes=15)

    # Kilitliyken doğru parola bile girmez.
    assert giris_isle(API_URL, ad, PAROLA, SIMDI + timedelta(minutes=14)) is None
    # 15 dakika dolunca girer ve sayaç temizlenir.
    assert giris_isle(API_URL, ad, PAROLA, SIMDI + timedelta(minutes=15, seconds=1)) is not None
    assert sayac_oku(kimlik) == (0, None)


@veritabani_gerekli
def test_db_olmayan_ve_pasif_kullanici_giremez():
    assert giris_isle(API_URL, "olmayan_kullanici_x", PAROLA, SIMDI) is None
    kimlik, ad = yeni_kullanici(aktif=False)
    assert giris_isle(API_URL, ad, PAROLA, SIMDI) is None
    assert kullanici_getir(API_URL, kimlik) is None


@veritabani_gerekli
def test_db_kullanici_getir_aktif_kullaniciyi_doner():
    kimlik, ad = yeni_kullanici(yetki=1)
    assert kullanici_getir(API_URL, kimlik) == {"id": kimlik, "kullanici_adi": ad, "yetki": 1}
    assert kullanici_getir(API_URL, 10**15) is None


@veritabani_gerekli
def test_db_siber_api_hesap_olusturamaz_parola_ve_yetki_degistiremez():
    kimlik, ad = yeni_kullanici(yetki=0)
    with psycopg.connect(API_URL) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO kullanicilar (kullanici_adi, parola_hash, yetki)"
                         " VALUES ('hile_x', %s, 1)", (HASH,))
    with psycopg.connect(API_URL) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE kullanicilar SET yetki = 1 WHERE id = %s", (kimlik,))
    with psycopg.connect(API_URL) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE kullanicilar SET parola_hash = %s WHERE id = %s", (HASH, kimlik))
