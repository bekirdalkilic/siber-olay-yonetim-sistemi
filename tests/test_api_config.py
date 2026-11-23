import pytest

from src.api.config import AyarHatasi, ortamdan_ayarlari_oku

URL = "postgresql://siber_api@localhost:5432/siber_olay_yonetimi"


def test_ayarlar_ortam_degiskenlerinden_okunur():
    ortam = {"API_KEY": "gizli-anahtar", "DATABASE_URL": URL, "PATH": "/usr/bin"}

    # Yalnızca bizim ayarlarımız alınır, PATH gibi diğer değişkenler alınmaz.
    assert ortamdan_ayarlari_oku(ortam) == {"API_KEY": "gizli-anahtar", "DATABASE_URL": URL}


@pytest.mark.parametrize("eksik", ["API_KEY", "DATABASE_URL"])
def test_eksik_degisken_hata_verir(eksik):
    ortam = {"API_KEY": "gizli-anahtar", "DATABASE_URL": URL}
    del ortam[eksik]

    with pytest.raises(AyarHatasi) as hata:
        ortamdan_ayarlari_oku(ortam)

    assert eksik in str(hata.value)


def test_bos_veya_bosluk_degeri_eksik_sayilir():
    ortam = {"API_KEY": "   ", "DATABASE_URL": URL}

    with pytest.raises(AyarHatasi):
        ortamdan_ayarlari_oku(ortam)


def test_hata_mesaji_gizli_degerleri_icermez():
    ortam = {"API_KEY": "COK-GIZLI-DEGER", "DATABASE_URL": ""}

    with pytest.raises(AyarHatasi) as hata:
        ortamdan_ayarlari_oku(ortam)

    assert "COK-GIZLI-DEGER" not in str(hata.value)
