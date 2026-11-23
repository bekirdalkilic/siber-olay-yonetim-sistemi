import ipaddress
import re
from datetime import datetime, timezone

# SQL şemasındaki olay_turu CHECK kuralıyla aynı liste olmalı.
OLAY_TURLERI = ("ssh_brute_force", "port_scan")

# ISO 8601 + zorunlu saat dilimi: 2026-11-24T14:05:09+03:00 veya ...Z
# Saat dilimi yoksa eşleşmez; çünkü DB sütunları timestamptz.
# re.ASCII: \d sadece 0-9 olsun (Arapça-Hint rakamları kabul edilmesin).
ZAMAN_DESENI = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?(Z|[+-]\d{2}:\d{2})",
    re.ASCII,
)


def iso_zaman_coz(metin):
    """ISO 8601 zamanını (saat dilimli) datetime'a çevirir; geçersizse None.

    metin: örn. "2026-11-24T14:05:09+03:00". Metin değilse de None döner.
    """
    if not isinstance(metin, str):
        return None
    # fullmatch: metnin TAMAMI desene uymalı (sondaki \n gibi artıklar reddedilir).
    if ZAMAN_DESENI.fullmatch(metin) is None:
        return None
    try:
        # Python 3.10 "Z" harfini tanımaz; +00:00 ile değiştiriyoruz.
        zaman = datetime.fromisoformat(metin.replace("Z", "+00:00"))
        # Fingerprint günü UTC'den hesaplıyor; 0001-01-01T00:00:00+03:00 gibi uç
        # tarihler UTC'ye çevrilemez (OverflowError). Bunları şimdiden reddediyoruz.
        zaman.astimezone(timezone.utc)
        return zaman
    except (ValueError, OverflowError):  # örn. 13. ay, +99:99, uç tarih
        return None


def ip_coz(deger):
    """Geçerli tek bir IPv4/IPv6 adresini metin olarak döndürür; değilse None.

    "10.0.0.0/8" (ağ) ve "fe80::1%eth0" (zone id) kabul edilmez: PostgreSQL'deki
    host_ip alanı sadece tek bir adres tutar.
    """
    if not isinstance(deger, str):
        return None
    try:
        ip = ipaddress.ip_address(deger)
    except ValueError:
        return None
    if getattr(ip, "scope_id", None):
        return None
    return str(ip)


def olay_dogrula(veri):
    """İstek gövdesini (JSON'dan çıkan Python nesnesi) doğrular.

    Döndürür: (temiz_olay, hatalar)
      - Hata yoksa: (temiz_olay sözlüğü, {})
      - Hata varsa: (None, {alan_adı: açıklama, ...}) — hatalar tek tek değil,
        hepsi birlikte toplanır; istemci hepsini bir seferde görür.
    Fazladan gelen alanlar yok sayılır.
    """
    if not isinstance(veri, dict):
        return None, {"govde": "İstek gövdesi bir JSON nesnesi ({...}) olmalı."}

    temiz = {}
    hatalar = {}

    cihaz_adi = veri.get("cihaz_adi")
    if isinstance(cihaz_adi, str) and cihaz_adi.strip():
        temiz["cihaz_adi"] = cihaz_adi.strip()
    else:
        hatalar["cihaz_adi"] = "Boş olmayan bir metin olmalı."

    olay_turu = veri.get("olay_turu")
    if olay_turu in OLAY_TURLERI:
        temiz["olay_turu"] = olay_turu
    else:
        hatalar["olay_turu"] = "Şunlardan biri olmalı: " + ", ".join(OLAY_TURLERI)

    kaynak_ip = ip_coz(veri.get("kaynak_ip"))
    if kaynak_ip is None:
        hatalar["kaynak_ip"] = "Geçerli bir IPv4/IPv6 adresi olmalı."
    else:
        temiz["kaynak_ip"] = kaynak_ip

    # hedef_ip: SSH olaylarında boş (alan yok ya da null) olabilir; port_scan'de zorunlu.
    # Doluysa her iki türde de geçerli bir IP olmalı.
    hedef_ham = veri.get("hedef_ip")
    if hedef_ham is None:
        if olay_turu == "port_scan":
            hatalar["hedef_ip"] = "port_scan olaylarında hedef_ip zorunlu."
        else:
            temiz["hedef_ip"] = None
    else:
        hedef_ip = ip_coz(hedef_ham)
        if hedef_ip is None:
            hatalar["hedef_ip"] = "Geçerli bir IPv4/IPv6 adresi olmalı (ya da null)."
        else:
            temiz["hedef_ip"] = hedef_ip

    zaman_mesaji = "Saat dilimli ISO 8601 olmalı, örn. 2026-11-24T14:05:09+03:00"

    olay_zamani = iso_zaman_coz(veri.get("olay_zamani"))
    if olay_zamani is None:
        hatalar["olay_zamani"] = zaman_mesaji
    else:
        temiz["olay_zamani"] = olay_zamani

    # ilk_gorulme isteğe bağlı: yoksa olay_zamani kullanılır (SSH alarmlarında yok).
    ilk_ham = veri.get("ilk_gorulme")
    if ilk_ham is None:
        if olay_zamani is not None:
            temiz["ilk_gorulme"] = olay_zamani
    else:
        ilk_gorulme = iso_zaman_coz(ilk_ham)
        if ilk_gorulme is None:
            hatalar["ilk_gorulme"] = zaman_mesaji
        elif olay_zamani is not None and ilk_gorulme > olay_zamani:
            # SQL'deki CHECK (son_gorulme >= ilk_gorulme) ile uyumlu.
            hatalar["ilk_gorulme"] = "olay_zamani'ndan sonra olamaz."
        else:
            temiz["ilk_gorulme"] = ilk_gorulme

    if hatalar:
        return None, hatalar
    return temiz, {}
