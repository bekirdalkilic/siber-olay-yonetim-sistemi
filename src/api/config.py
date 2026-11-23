import os

# Uygulamanın çalışması için ortam değişkeni olarak verilmesi ZORUNLU ayarlar.
GEREKLI_DEGISKENLER = ("API_KEY", "DATABASE_URL")


class AyarHatasi(Exception):
    """Gerekli bir ortam değişkeni eksik veya boşsa yükseltilir."""


def ortamdan_ayarlari_oku(ortam=None):
    """Gerekli ayarları ortam değişkenlerinden okuyup sözlük olarak döndürür.

    ortam: değişken adı -> değer sözlüğü. Verilmezse gerçek ortam (os.environ) kullanılır.
    Eksik veya boş değişken varsa AyarHatasi yükselir. Hata mesajına yalnızca
    değişkenin ADI yazılır, değeri (anahtar/parola) asla yazılmaz.
    """
    if ortam is None:
        ortam = os.environ

    eksikler = []
    for ad in GEREKLI_DEGISKENLER:
        if not ortam.get(ad, "").strip():
            eksikler.append(ad)

    if eksikler:
        raise AyarHatasi("Eksik ortam değişkenleri: " + ", ".join(eksikler))

    return {
        "API_KEY": ortam["API_KEY"],
        "DATABASE_URL": ortam["DATABASE_URL"],
    }


SECRET_KEY_MIN_UZUNLUK = 32


def web_ayarlarini_oku(ortam=None):
    """Web arayüzü (giriş sayfaları) için oturum ayarlarını okur.

    SECRET_KEY: oturum çerezini imzalar; en az 32 karakter olmalı. Yoksa sözlükte yer
        almaz ve web arayüzü açılmaz (olay API'si bundan etkilenmez).
    COOKIE_SECURE: "0" ya da "false" yazılırsa çerez düz HTTP'de de gönderilir
        (sadece HTTPS olmayan, localhost dışı denemeler için). Varsayılan: Secure.
    Anahtar kısa/zayıfsa AyarHatasi yükselir; mesajda değeri değil sadece adı yazar.
    """
    if ortam is None:
        ortam = os.environ

    ayarlar = {
        "SESSION_COOKIE_SECURE": ortam.get("COOKIE_SECURE", "1").strip().lower() not in ("0", "false"),
    }
    anahtar = ortam.get("SECRET_KEY", "")
    if anahtar.strip():
        if len(anahtar) < SECRET_KEY_MIN_UZUNLUK:
            raise AyarHatasi(f"SECRET_KEY en az {SECRET_KEY_MIN_UZUNLUK} karakter olmalı")
        ayarlar["SECRET_KEY"] = anahtar
    return ayarlar
