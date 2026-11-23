"""Web arayüzü: giriş, çıkış ve rol bazlı sayfalar (Flask Blueprint).

Akış: /giris (form) -> CSRF kontrolü -> kullanici.giris_isle -> oturum -> /yonetici ya da /analist
Yetki: yetki=1 yönetici, yetki=0 analist. Korumalı sayfalarda yetki_gerekli kullanılır.
"""
import hmac
import secrets
from functools import wraps

import psycopg
from flask import Blueprint, current_app, g, redirect, render_template, request, session, url_for

from src.api.kullanici import giris_isle, kullanici_getir

web = Blueprint("web", __name__)

ANALIST = 0
YONETICI = 1

# Kullanıcı yok / parola yanlış / hesap kilitli / hesap pasif: HEPSİNDE aynı mesaj.
# Farklı mesajlar saldırgana hangi kullanıcı adlarının var olduğunu söylerdi.
GENEL_GIRIS_HATASI = "Kullanıcı adı veya parola hatalı ya da hesap geçici olarak kilitli."


# ---------- CSRF ----------
# CSRF: başka bir sitenin, tarayıcındaki açık oturumu kullanarak senin adına form
# göndermesi. Önlem: her formda oturuma özel gizli bir token olur; başka site bunu bilemez.

def csrf_token():
    """Oturumdaki CSRF token'ını döndürür (yoksa üretir). Şablonlarda csrf_token() olarak kullanılır."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def csrf_gecerli_mi():
    """Formdan gelen csrf_token, oturumdakiyle aynı mı? (sabit sürede karşılaştırır)"""
    beklenen = session.get("csrf_token", "")
    gelen = request.form.get("csrf_token", "")
    if not beklenen:
        return False
    return hmac.compare_digest(gelen.encode("utf-8"), beklenen.encode("utf-8"))


@web.app_context_processor
def sablon_degiskenleri():
    return {"csrf_token": csrf_token}


# ---------- yardımcılar ----------

def rol_sayfasi(yetki):
    """Yetkiye göre kullanıcının ana sayfasının adresi: yönetici -> /yonetici, analist -> /analist."""
    return url_for("web.yonetici") if yetki == YONETICI else url_for("web.analist")


def veritabani_hatasi_sayfasi(hata):
    """Veritabanı hatasında sabit bir 503 sayfası döner; hata metni ne sayfaya ne loga yazılır."""
    current_app.logger.error(
        "Web: veritabanı hatası (hata: %s, sqlstate: %s)", type(hata).__name__, hata.sqlstate
    )
    sayfa = render_template(
        "hata.html",
        baslik="Hizmet kullanılamıyor",
        mesaj="Sistem şu an yanıt veremiyor. Lütfen daha sonra tekrar deneyin.",
        geri_url=url_for("web.giris"),
    )
    return sayfa, 503


def yetki_gerekli(en_az_yetki):
    """Bir sayfayı en az verilen yetkiye sahip kullanıcılara açar.

    en_az_yetki: ANALIST (0) ya da YONETICI (1). Yönetici (1) analist (0) sayfalarını da açabilir.
    - Oturum yoksa            -> /giris'e yönlendirir (302)
    - Kullanıcı artık yoksa/pasifse -> oturumu siler, /giris'e yönlendirir
    - Yetkisi yetmiyorsa      -> 403 Forbidden
    Kullanıcı HER istekte veritabanından okunur; çerezdeki bilgiye güvenilmez.
    """
    def dekorator(view):
        @wraps(view)
        def kontrol(*args, **kwargs):
            kullanici_id = session.get("kullanici_id")
            if not isinstance(kullanici_id, int) or isinstance(kullanici_id, bool):
                return redirect(url_for("web.giris"))
            try:
                kullanici = kullanici_getir(current_app.config["DATABASE_URL"], kullanici_id)
            except psycopg.Error as hata:
                return veritabani_hatasi_sayfasi(hata)
            if kullanici is None:
                session.clear()
                return redirect(url_for("web.giris"))
            if kullanici["yetki"] < en_az_yetki:
                sayfa = render_template(
                    "hata.html",
                    baslik="Erişim reddedildi",
                    mesaj="Bu sayfayı görüntüleme yetkiniz yok.",
                    geri_url=rol_sayfasi(kullanici["yetki"]),
                    kullanici=kullanici,
                )
                return sayfa, 403
            g.kullanici = kullanici
            return view(*args, **kwargs)
        return kontrol
    return dekorator


# ---------- sayfalar ----------

@web.get("/")
def ana_sayfa():
    return redirect(url_for("web.giris"))


@web.route("/giris", methods=["GET", "POST"])
def giris():
    if request.method == "GET":
        csrf_token()  # oturumu ve token'ı hazırla
        return render_template("giris.html")

    if not csrf_gecerli_mi():
        return render_template(
            "hata.html",
            baslik="Güvenlik doğrulaması başarısız",
            mesaj="Form süresi dolmuş olabilir. Giriş sayfasını yenileyip tekrar deneyin.",
            geri_url=url_for("web.giris"),
        ), 403

    kullanici_adi = request.form.get("kullanici_adi", "").strip()
    parola = request.form.get("parola", "")
    try:
        kullanici = giris_isle(current_app.config["DATABASE_URL"], kullanici_adi, parola)
    except psycopg.Error as hata:
        return veritabani_hatasi_sayfasi(hata)

    if kullanici is None:
        # 401 Unauthorized: kimlik doğrulanamadı. Parola forma geri YAZILMAZ.
        return render_template(
            "giris.html", hata=GENEL_GIRIS_HATASI, kullanici_adi=kullanici_adi
        ), 401

    session.clear()  # eski oturum verisini at (oturum sabitleme saldırısına karşı)
    session.permanent = True  # PERMANENT_SESSION_LIFETIME (30 dk) geçerli olsun
    session["kullanici_id"] = kullanici["id"]
    csrf_token()  # yeni oturum için yeni token
    return redirect(rol_sayfasi(kullanici["yetki"]))


@web.post("/cikis")
def cikis():
    """Çıkış sadece POST + CSRF ile yapılır (bir link/resim ile tetiklenemesin)."""
    if not csrf_gecerli_mi():
        return render_template(
            "hata.html",
            baslik="Güvenlik doğrulaması başarısız",
            mesaj="Çıkış yapılamadı. Sayfayı yenileyip tekrar deneyin.",
            geri_url=url_for("web.giris"),
        ), 403
    session.clear()
    return redirect(url_for("web.giris"))


@web.get("/yonetici")
@yetki_gerekli(YONETICI)
def yonetici():
    return render_template("yonetici.html", kullanici=g.kullanici)


@web.get("/analist")
@yetki_gerekli(ANALIST)
def analist():
    return render_template("analist.html", kullanici=g.kullanici)


@web.after_request
def guvenlik_basliklari(yanit):
    # Sadece kendi sitemizden kaynak yükle, sayfa başka sitede çerçevelenmesin,
    # tarayıcı içerik türünü tahmin etmesin, giriş sayfaları önbelleğe alınmasın.
    yanit.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
    yanit.headers["X-Frame-Options"] = "DENY"
    yanit.headers["X-Content-Type-Options"] = "nosniff"
    yanit.headers["Cache-Control"] = "no-store"
    return yanit
