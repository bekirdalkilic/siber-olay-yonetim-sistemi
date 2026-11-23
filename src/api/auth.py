import hmac


def api_anahtari_gecerli_mi(gelen_anahtar, beklenen_anahtar):
    """Gelen X-API-KEY değeri beklenen anahtarla aynı mı? True/False döndürür.

    gelen_anahtar: istek başlığından gelen metin (başlık yoksa None).
    beklenen_anahtar: sunucunun ortam değişkeninden okuduğu gerçek anahtar.

    Neden == değil de hmac.compare_digest? Sıradan == ilk farklı karakterde durur;
    cevap süresi, tahminin kaç karakterinin doğru olduğunu sızdırabilir.
    compare_digest her durumda aynı sürede çalışır. Metinleri bytes'a çeviriyoruz,
    çünkü Türkçe karakter gibi ASCII dışı harflerde str karşılaştırması hata verir.
    """
    if not gelen_anahtar:
        return False
    return hmac.compare_digest(
        gelen_anahtar.encode("utf-8"),
        beklenen_anahtar.encode("utf-8"),
    )
