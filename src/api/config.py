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
