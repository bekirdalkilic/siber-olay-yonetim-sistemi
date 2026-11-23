import json

import psycopg
from flask import Flask, request
from werkzeug.exceptions import HTTPException

from src.api.auth import api_anahtari_gecerli_mi
from src.api.config import ortamdan_ayarlari_oku
from src.api.db import olay_isle
from src.api.validation import olay_dogrula


def hata_yaniti(durum_kodu, hata, mesaj, alanlar=None):
    """(JSON gövde, HTTP durum kodu) çifti döndürür; Flask bunu yanıta çevirir.

    durum_kodu: 401, 400, 422, 501 gibi HTTP kodu.
    hata: makinenin okuyacağı kısa ad (örn. "bozuk_json").
    mesaj: insanın okuyacağı açıklama.
    alanlar: sadece doğrulama hatalarında, {alan: açıklama} sözlüğü.
    """
    govde = {"hata": hata, "mesaj": mesaj}
    if alanlar:
        govde["alanlar"] = alanlar
    return govde, durum_kodu


def create_app(test_ayarlari=None):
    """Flask uygulamasını kurup döndürür (application factory).

    test_ayarlari verilmezse ayarlar ortam değişkenlerinden okunur; eksik ayar
    varsa AyarHatasi ile uygulama hiç başlamaz. Testler kendi ayarlarını verir.
    """
    app = Flask(__name__)

    if test_ayarlari is None:
        app.config.from_mapping(ortamdan_ayarlari_oku())
    else:
        app.config.from_mapping(test_ayarlari)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/api/v1/events")
    def olay_al():
        # 1) Anahtar kontrolü EN BAŞTA: yetkisiz istemcinin gövdesi hiç işlenmez.
        gelen_anahtar = request.headers.get("X-API-KEY")
        if not api_anahtari_gecerli_mi(gelen_anahtar, app.config["API_KEY"]):
            # Loga anahtarın kendisini ASLA yazmıyoruz; sadece istemci adresini.
            app.logger.warning(
                "Reddedilen istek: geçersiz API anahtarı (istemci: %s)",
                request.remote_addr,
            )
            return hata_yaniti(
                401, "gecersiz_api_anahtari", "X-API-KEY başlığı eksik veya geçersiz."
            )

        # 2) JSON ayrıştırma. Content-Type başlığına bakmıyoruz, gövdeyi metin olarak
        # okuyup kendimiz çözüyoruz. RecursionError: "[[[[..." gibi aşırı iç içe gövde.
        try:
            veri = json.loads(request.get_data(as_text=True))
        except (ValueError, RecursionError):
            return hata_yaniti(400, "bozuk_json", "İstek gövdesi geçerli bir JSON değil.")

        # 3) Alan doğrulama.
        temiz_olay, hatalar = olay_dogrula(veri)
        if hatalar:
            return hata_yaniti(
                422, "dogrulama_hatasi", "Olay verisi geçersiz.", alanlar=hatalar
            )

        # 4) Veritabanına kayıt. Hata metnini (içinde bağlantı bilgisi olabilir)
        # ne yanıta ne loga yazıyoruz; sadece hata sınıfı adı ve SQLSTATE kodu.
        try:
            sonuc = olay_isle(app.config["DATABASE_URL"], temiz_olay)
        except psycopg.OperationalError as hata:
            # Bağlanılamadı, giriş reddedildi, zaman aşımı vb.: geçici sorun.
            app.logger.error(
                "Veritabanına ulaşılamadı (hata: %s, sqlstate: %s)",
                type(hata).__name__,
                hata.sqlstate,
            )
            return hata_yaniti(
                503,
                "veritabani_kullanilamiyor",
                "Veritabanına şu an ulaşılamıyor. Daha sonra tekrar deneyin.",
            )
        except psycopg.Error as hata:
            app.logger.error(
                "Veritabanı hatası (hata: %s, sqlstate: %s)",
                type(hata).__name__,
                hata.sqlstate,
            )
            return hata_yaniti(
                500, "veritabani_hatasi", "Olay kaydedilirken bir veritabanı hatası oluştu."
            )

        if sonuc is None:
            return hata_yaniti(
                422,
                "bilinmeyen_cihaz",
                "Olayı gönderen cihaz kayıtlı değil.",
                alanlar={"cihaz_adi": "Kayıtlı bir cihaz adı olmalı."},
            )

        olay_id, tekrar_sayisi = sonuc
        yeni_olay = tekrar_sayisi == 1  # 1 ise satır şimdi eklendi; >1 ise güncellendi
        govde = {"olay_id": olay_id, "tekrar_sayisi": tekrar_sayisi, "yeni_olay": yeni_olay}
        return govde, (201 if yeni_olay else 200)

    @app.errorhandler(HTTPException)
    def http_hatasi(hata):
        # 404, 405, 500 gibi Flask'ın kendi hataları da JSON dönsün diye.
        # get_response() Allow gibi başlıkları korur (405'te hangi metotlar serbest).
        yanit = hata.get_response()
        yanit.data = json.dumps(
            {"hata": hata.name.lower().replace(" ", "_"), "mesaj": hata.description},
            ensure_ascii=False,
        )
        yanit.content_type = "application/json"
        return yanit

    return app
