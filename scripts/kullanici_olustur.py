"""Yönetici ya da analist hesabı oluşturur (veritabanı YÖNETİCİ hesabıyla çalışır).

Kullanım (proje klasöründen; ADMIN_DATABASE_URL içinde parola olmamalı):
    export ADMIN_DATABASE_URL="postgresql://postgres@localhost/siber_olay_yonetimi"
    python -m scripts.kullanici_olustur --kullanici-adi yonetici1 --yetki yonetici
    python -m scripts.kullanici_olustur --kullanici-adi analist1  --yetki analist
    (DB yönetici parolası ~/.pgpass'ten okunmuyorsa: --db-parolasini-sor ekleyin)

Güvenlik:
 - Kullanıcının parolası getpass ile sorulur: ekrana yazılmaz, komut satırına, kaynak koda,
   ortam değişkenine ya da loga girmez. Veritabanına yalnızca Argon2id hash'i gider.
 - siber_api rolüyle çalışmayı reddeder (o rolün INSERT yetkisi zaten yoktur).
 - Var olan bir kullanıcının üzerine yazmaz.
"""
import argparse
import getpass
import os
import re
import sys

import psycopg
from argon2 import PasswordHasher

from src.api.kullanici import KULLANICI_ADI_MAX, PAROLA_MAX

YETKILER = {"yonetici": 1, "analist": 0}
KULLANICI_ADI_DESENI = re.compile(r"[A-Za-z0-9_.-]{3,%d}" % KULLANICI_ADI_MAX, re.ASCII)
PAROLA_MIN = 10

KULLANICI_EKLE = """
INSERT INTO kullanicilar (kullanici_adi, parola_hash, yetki)
VALUES (%s, %s, %s)
RETURNING id
"""


def kullanici_adi_gecerli_mi(kullanici_adi):
    """3-50 karakter; sadece harf (a-z), rakam, nokta, alt çizgi ve tire."""
    return KULLANICI_ADI_DESENI.fullmatch(kullanici_adi) is not None


def parola_hatasi(parola, kullanici_adi):
    """Parola uygunsa None, değilse nedenini anlatan metin döndürür."""
    if len(parola) < PAROLA_MIN:
        return f"Parola en az {PAROLA_MIN} karakter olmalı."
    if len(parola) > PAROLA_MAX:
        return f"Parola en fazla {PAROLA_MAX} karakter olabilir."
    if "\x00" in parola:
        return "Parola geçersiz karakter içeriyor."
    if parola.lower() == kullanici_adi.lower():
        return "Parola kullanıcı adıyla aynı olamaz."
    return None


def parola_hashle(parola, hasher=None):
    """Parolayı Argon2id ile özetler ("$argon2id$..." metni döner). Hash'e tuz otomatik eklenir."""
    if hasher is None:
        hasher = PasswordHasher()  # varsayılan algoritma Argon2id
    return hasher.hash(parola)


def kullanici_ekle(cur, kullanici_adi, parola_hash, yetki):
    """kullanicilar tablosuna yeni satır ekler, yeni kullanıcının id'sini döndürür.

    cur: yönetici bağlantısının cursor'ı. yetki: 1 yönetici, 0 analist.
    Aynı kullanıcı adı varsa psycopg.errors.UniqueViolation fırlar (hiçbir şey değişmez).
    """
    cur.execute(KULLANICI_EKLE, (kullanici_adi, parola_hash, yetki))
    return cur.fetchone()[0]


def yonetici_baglantisi(url, db_parola=None):
    """Yönetici hesabıyla veritabanına bağlanır. db_parola verilirse URL'ye yazılmadan iletilir."""
    secenekler = {"connect_timeout": 5}
    if db_parola is not None:
        secenekler["password"] = db_parola
    return psycopg.connect(url, **secenekler)


def parolayi_sor():
    """Kullanıcı parolasını gizli (ekrana yansımadan) iki kez sorar; uyuşmazsa None döndürür."""
    parola = getpass.getpass("Yeni hesabın parolası (ekrana yazılmaz): ")
    tekrar = getpass.getpass("Parola (tekrar): ")
    return parola if parola == tekrar else None


def main(argv=None, ortam=None):
    """Çıkış kodu: 0 başarılı, 1 veritabanı hatası/kullanıcı zaten var, 2 girdi/ayar hatası."""
    ortam = os.environ if ortam is None else ortam
    ayristirici = argparse.ArgumentParser(
        prog="python -m scripts.kullanici_olustur",
        description="Yönetici ya da analist hesabı oluşturur.",
    )
    ayristirici.add_argument("--kullanici-adi", required=True)
    ayristirici.add_argument("--yetki", required=True, choices=sorted(YETKILER))
    ayristirici.add_argument("--db-parolasini-sor", action="store_true",
                             help="PostgreSQL yönetici parolasını gizli olarak sor (URL'de parola yazmayın)")
    args = ayristirici.parse_args(argv)

    url = ortam.get("ADMIN_DATABASE_URL", "").strip()
    if not url:
        print("HATA: ADMIN_DATABASE_URL ortam değişkeni tanımlı değil.", file=sys.stderr)
        return 2
    if not kullanici_adi_gecerli_mi(args.kullanici_adi):
        print("HATA: kullanıcı adı 3-50 karakter olmalı; yalnızca harf, rakam, '.', '_' ve '-' içerebilir.",
              file=sys.stderr)
        return 2

    parola = parolayi_sor()
    if parola is None:
        print("HATA: iki parola birbirinden farklı.", file=sys.stderr)
        return 2
    hata_metni = parola_hatasi(parola, args.kullanici_adi)
    if hata_metni:
        print(f"HATA: {hata_metni}", file=sys.stderr)
        return 2

    db_parola = getpass.getpass("PostgreSQL yönetici parolası: ") if args.db_parolasini_sor else None
    parola_hash = parola_hashle(parola)
    del parola  # düz parola bundan sonra gerekmiyor

    try:
        with yonetici_baglantisi(url, db_parola) as baglanti:
            with baglanti.cursor() as cur:
                cur.execute("SELECT current_user")
                if cur.fetchone()[0] == "siber_api":
                    print("HATA: siber_api ile hesap oluşturulamaz; yönetici DB hesabını kullanın.",
                          file=sys.stderr)
                    return 2
                kullanici_id = kullanici_ekle(cur, args.kullanici_adi, parola_hash, YETKILER[args.yetki])
    except psycopg.errors.UniqueViolation:
        print(f"HATA: '{args.kullanici_adi}' kullanıcı adı zaten var; mevcut hesaba dokunulmadı.",
              file=sys.stderr)
        return 1
    except psycopg.Error as hata:
        # Hata metni yazdırılmaz (bağlantı bilgisi içerebilir); sınıf adı ve SQLSTATE yeter.
        print(f"HATA: veritabanı işlemi başarısız ({type(hata).__name__}, sqlstate: {hata.sqlstate}).",
              file=sys.stderr)
        return 1

    print(f"Hesap oluşturuldu: kullanıcı adı={args.kullanici_adi}, yetki={args.yetki}, id={kullanici_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
