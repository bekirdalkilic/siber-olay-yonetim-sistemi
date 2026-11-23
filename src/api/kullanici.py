"""Kullanıcı doğrulama: Argon2id parola kontrolü, hatalı giriş sayacı ve hesap kilidi.

Tablo: kullanicilar (database/migrations/001_kullanicilar.sql). siber_api rolü bu tabloda
yalnızca SELECT ve UPDATE (hatali_giris, kilit_bitis) yapabilir; kullanıcı ekleyemez.
"""
from datetime import datetime, timedelta, timezone

import psycopg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

HATALI_GIRIS_ESIGI = 5  # bu kadar ARDIŞIK hatalı parola hesabı kilitler
KILIT_SURESI = timedelta(minutes=15)

# Girdi sınırları: devasa girdilerle sunucuyu yormayı engeller.
KULLANICI_ADI_MAX = 50  # kullanicilar.kullanici_adi VARCHAR(50)
PAROLA_MAX = 256

# PasswordHasher() varsayılanı Argon2id'dir (güvenli, bellek kullanan bir parola özeti).
_hasher = PasswordHasher()
# Kullanıcı yoksa da bir Argon2 doğrulaması çalıştırırız; böylece "kullanıcı var mı"
# bilgisi cevap süresinden sızmaz.
_SAHTE_HASH = _hasher.hash("bu-parola-hicbir-hesaba-ait-degil")

# FOR UPDATE: bu satırı işlem bitene kadar kilitler. Aynı hesaba aynı anda gelen iki
# deneme sırayla işlenir, sayaç şaşmaz. (siber_api'nin UPDATE yetkisi buna yeter.)
GIRIS_SORGUSU = """
SELECT id, kullanici_adi, parola_hash, yetki, aktif_mi, hatali_giris, kilit_bitis
FROM kullanicilar
WHERE kullanici_adi = %s
FOR UPDATE
"""
SAYAC_GUNCELLE = "UPDATE kullanicilar SET hatali_giris = %s, kilit_bitis = %s WHERE id = %s"
KULLANICI_GETIR = "SELECT id, kullanici_adi, yetki FROM kullanicilar WHERE id = %s AND aktif_mi"


def girdi_gecerli_mi(kullanici_adi, parola):
    """Giriş formundan gelen değerler makul mu? (metin, boş değil, sınırlar içinde, NUL yok)

    NUL karakteri ("\\x00") PostgreSQL metin alanlarına konamaz; hata vermesin diye elenir.
    """
    if not isinstance(kullanici_adi, str) or not isinstance(parola, str):
        return False
    if not kullanici_adi or not parola:
        return False
    if len(kullanici_adi) > KULLANICI_ADI_MAX or len(parola) > PAROLA_MAX:
        return False
    return "\x00" not in kullanici_adi and "\x00" not in parola


def parola_dogru_mu(parola_hash, parola):
    """Parola, kayıtlı Argon2id hash'iyle eşleşiyor mu? True/False döndürür.

    parola_hash: veritabanındaki "$argon2id$..." metni. parola: kullanıcının yazdığı metin.
    Hash'in içinde algoritma ayarları da yazılı olduğu için doğrulama onlarla yapılır.
    Bozuk hash da False döner (uygulama çökmez).
    """
    try:
        return _hasher.verify(parola_hash, parola)
    except (VerificationError, InvalidHashError):
        return False


def giris_sonucu_hesapla(hatali_giris, kilit_bitis, aktif_mi, parola_dogru, simdi):
    """Bir giriş denemesinin sonucunu hesaplar. VERİTABANINA DOKUNMAZ (saf fonksiyon).

    hatali_giris: şimdiye kadarki ardışık hatalı deneme sayısı.
    kilit_bitis: kilidin biteceği an (saat dilimli datetime) ya da None.
    aktif_mi: hesap aktif mi. parola_dogru: yazılan parola doğru mu. simdi: şu an.
    Döndürür: (giris_basarili, yeni_hatali_giris, yeni_kilit_bitis)
    """
    kilitli = kilit_bitis is not None and kilit_bitis > simdi  # tam kilit_bitis anında açılır

    # Pasif ya da kilitli hesap: parola doğru olsa bile giriş yok, sayaç ve kilit değişmez
    # (böylece saldırgan kilidi uzatamaz).
    if not aktif_mi or kilitli:
        return False, hatali_giris, kilit_bitis

    if parola_dogru:
        return True, 0, None  # başarılı giriş sayacı ve eski kilidi temizler

    # Yanlış parola. Burada kilit_bitis boş değilse, kilit süresi dolmuş demektir:
    # yeni bir deneme dizisi başlar.
    yeni_sayi = 1 if kilit_bitis is not None else hatali_giris + 1
    yeni_kilit = simdi + KILIT_SURESI if yeni_sayi >= HATALI_GIRIS_ESIGI else None
    return False, yeni_sayi, yeni_kilit


def giris_dene(cur, kullanici_adi, parola, simdi):
    """Kullanıcıyı doğrular, sayaç/kilidi günceller. Başarılıysa kullanıcı sözlüğü, değilse None.

    cur: açık psycopg cursor'ı (çağıran transaction'ı yönetir; hata yoksa COMMIT edilir,
        yani başarısız girişin sayaç artışı da kaydedilir).
    simdi: saat dilimli datetime (testlerde sabit bir an verilebilsin diye parametre).
    Başarısızlığın nedeni (kullanıcı yok / parola yanlış / kilitli / pasif) DIŞARI VERİLMEZ.
    """
    cur.execute(GIRIS_SORGUSU, (kullanici_adi,))
    satir = cur.fetchone()

    if satir is None:
        # Kullanıcı yok. Yine de bir Argon2 doğrulaması yapılır (sahte hash'e karşı);
        # böylece cevap süresine bakarak "bu kullanıcı var mı" anlaşılamaz.
        parola_dogru_mu(_SAHTE_HASH, parola)
        return None

    kullanici_id, ad, parola_hash, yetki, aktif_mi, hatali_giris, kilit_bitis = satir
    dogru = parola_dogru_mu(parola_hash, parola)
    basarili, yeni_sayi, yeni_kilit = giris_sonucu_hesapla(
        hatali_giris, kilit_bitis, aktif_mi, dogru, simdi
    )
    if (yeni_sayi, yeni_kilit) != (hatali_giris, kilit_bitis):
        cur.execute(SAYAC_GUNCELLE, (yeni_sayi, yeni_kilit, kullanici_id))

    if basarili:
        return {"id": kullanici_id, "kullanici_adi": ad, "yetki": yetki}
    return None


def giris_isle(database_url, kullanici_adi, parola, simdi=None):
    """Bağlantı açıp giris_dene'yi tek transaction'da çalıştırır; kullanıcı sözlüğü ya da None.

    Bağlantı/veritabanı hataları psycopg.Error olarak yukarı (web.py'ye) fırlar.
    """
    if not girdi_gecerli_mi(kullanici_adi, parola):
        return None
    if simdi is None:
        simdi = datetime.now(timezone.utc)
    with psycopg.connect(database_url, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            return giris_dene(cur, kullanici_adi, parola, simdi)


def kullanici_getir(database_url, kullanici_id):
    """Oturumdaki kullanıcı id'sine karşılık AKTİF kullanıcıyı döndürür; yoksa/pasifse None.

    Her korumalı sayfada çağrılır: hesap pasifleştirilirse ya da yetkisi değişirse
    eski oturum hemen geçersiz olur.
    """
    with psycopg.connect(database_url, connect_timeout=5) as conn:
        satir = conn.execute(KULLANICI_GETIR, (kullanici_id,)).fetchone()
    if satir is None:
        return None
    return {"id": satir[0], "kullanici_adi": satir[1], "yetki": satir[2]}
