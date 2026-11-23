"""SSH log dosyasını okuyup brute-force alarmlarını API'ye gönderen komut.

Akış: log dosyası -> parser -> dedektör -> alarm -> JSON -> HTTP POST -> API -> PostgreSQL
Çalıştırma (proje klasöründen):
    python -m src.ssh_ajan --log data/ssh_demo_bruteforce.log --yil 2026 \\
        --cihaz-adi demo-fw-01 --saat-dilimi Europe/Istanbul
API anahtarı sadece API_KEY ortam değişkeninden okunur; ekrana yazılmaz.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from src.log_reader import read_log_lines
from src.ssh_detector import detect_ssh_bruteforce
from src.ssh_parser import parse_sshd_line

VARSAYILAN_API_URL = "http://127.0.0.1:5000"


class AjanHatasi(Exception):
    """Ayar eksik/hatalı ya da API'ye ulaşılamadı. Mesajlarda gizli bilgi bulunmaz."""


def ssh_alarmlari_bul(log_yolu, yil):
    """Log dosyasından SSH brute-force alarmlarını üretir (mevcut modülleri çağırır).

    log_yolu: SSH log dosyasının yolu. Dosya yoksa FileNotFoundError yükselir.
    yil: syslog'da yıl olmadığı için dışarıdan verilen yıl (örn. 2026).
    Dönüş: detect_ssh_bruteforce'un alarm sözlükleri listesi.
    """
    satirlar = read_log_lines(log_yolu)
    # Alakasız/bozuk satırlar için parse_sshd_line None döner; dedektör None'ları atlar.
    olaylar = [parse_sshd_line(satir["ham"]) for satir in satirlar]
    return detect_ssh_bruteforce(olaylar, yil)


def zaman_dilimi_coz(ad):
    """"Europe/Istanbul" gibi bir adı ZoneInfo nesnesine çevirir.

    ad: logların YAZILDIĞI makinenin saat dilimi. Boşsa ya da tanınmıyorsa hata verir;
    varsayılan saat dilimi YOK, çünkü yanlış varsayım olayları saatlerce kaydırır.
    """
    if ad is None or not ad.strip():
        raise AjanHatasi("Log saat dilimi verilmedi (--saat-dilimi ya da LOG_SAAT_DILIMI).")
    try:
        return ZoneInfo(ad.strip())
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise AjanHatasi(f"Bilinmeyen saat dilimi: {ad!r} (örnek: Europe/Istanbul).") from None


def alarmi_olaya_cevir(alarm, cihaz_adi, saat_dilimi):
    """Dedektör alarmını API'nin kabul ettiği JSON sözlüğüne çevirir.

    alarm: detect_ssh_bruteforce'un tek alarm sözlüğü (tespit_zamani saat dilimsizdir).
    cihaz_adi: DB'deki cihazlar.cihaz_adi değeri (örn. "demo-fw-01").
    saat_dilimi: zaman_dilimi_coz'un döndürdüğü ZoneInfo.
    API saat dilimli zaman ister; saat dilimsiz zamana verdiğin saat dilimi eklenir
    (örn. 13:58:18 + Europe/Istanbul -> 2026-11-24T13:58:18+03:00).
    """
    zaman = alarm["tespit_zamani"]
    if zaman.tzinfo is not None:
        raise AjanHatasi("Beklenmedik durum: alarm zamanı zaten saat dilimli.")
    return {
        "cihaz_adi": cihaz_adi,
        "olay_turu": alarm["olay_turu"],
        "kaynak_ip": alarm["kaynak_ip"],
        "olay_zamani": zaman.replace(tzinfo=saat_dilimi).isoformat(),
    }


def olay_gonder(api_url, api_anahtari, olay, zaman_asimi=10):
    """Olayı API'ye POST eder. (HTTP durum kodu, yanıt JSON sözlüğü) döndürür.

    api_url: örn. "http://127.0.0.1:5000". api_anahtari: X-API-KEY başlığına konur.
    olay: alarmi_olaya_cevir'in sözlüğü. zaman_asimi: bekleme süresi (saniye).
    4xx/5xx yanıtlar hata FIRLATMAZ (kod ve gövde döner); sadece sunucuya hiç
    ulaşılamazsa AjanHatasi fırlar.
    """
    if not api_url.startswith(("http://", "https://")):
        raise AjanHatasi("API adresi http:// ya da https:// ile başlamalı.")
    adres = api_url.rstrip("/") + "/api/v1/events"
    istek = urllib.request.Request(
        adres,
        data=json.dumps(olay).encode("utf-8"),
        headers={"X-API-KEY": api_anahtari, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(istek, timeout=zaman_asimi) as yanit:
            durum, govde = yanit.status, yanit.read()
    except urllib.error.HTTPError as hata:  # 4xx/5xx: yanıt gövdesi yine de vardır
        durum, govde = hata.code, hata.read()
    except UnicodeEncodeError:
        raise AjanHatasi("API anahtarı ASCII olmayan karakter içeriyor.") from None
    except (urllib.error.URLError, OSError):
        raise AjanHatasi(f"API'ye ulaşılamadı: {adres}") from None
    try:
        veri = json.loads(govde.decode("utf-8"))
    except ValueError:
        veri = {}
    return durum, veri


def argumanlari_oku(argv, ortam):
    ayristirici = argparse.ArgumentParser(
        prog="python -m src.ssh_ajan",
        description="SSH log dosyasındaki brute-force alarmlarını API'ye gönderir.",
    )
    ayristirici.add_argument("--log", required=True, help="SSH log dosyası")
    ayristirici.add_argument("--yil", type=int, required=True,
                             help="logun yılı (syslog'da yıl yoktur), örn. 2026")
    ayristirici.add_argument("--cihaz-adi", default=ortam.get("CIHAZ_ADI"),
                             help="DB'deki cihaz adı (ya da CIHAZ_ADI ortam değişkeni)")
    ayristirici.add_argument("--saat-dilimi", default=ortam.get("LOG_SAAT_DILIMI"),
                             help="logun saat dilimi, örn. Europe/Istanbul (ya da LOG_SAAT_DILIMI)")
    ayristirici.add_argument("--api-url", default=ortam.get("API_URL", VARSAYILAN_API_URL),
                             help=f"API adresi (varsayılan {VARSAYILAN_API_URL})")
    ayristirici.add_argument("--kuru-calistirma", action="store_true",
                             help="sadece JSON'u yazdır, API'ye gönderme")
    return ayristirici.parse_args(argv)


def main(argv=None, ortam=None):
    """Komutu çalıştırır; çıkış kodu döndürür: 0 başarılı, 1 gönderim hatası, 2 ayar/dosya hatası."""
    ortam = os.environ if ortam is None else ortam
    args = argumanlari_oku(argv, ortam)
    api_anahtari = ortam.get("API_KEY", "")

    try:
        saat_dilimi = zaman_dilimi_coz(args.saat_dilimi)
        if not (args.cihaz_adi or "").strip():
            raise AjanHatasi("Cihaz adı verilmedi (--cihaz-adi ya da CIHAZ_ADI).")
        if not args.kuru_calistirma and not api_anahtari.strip():
            raise AjanHatasi("API_KEY ortam değişkeni tanımlı değil.")
        alarmlar = ssh_alarmlari_bul(args.log, args.yil)
    except AjanHatasi as hata:
        print(f"HATA: {hata}", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print(f"HATA: log dosyası bulunamadı: {args.log}", file=sys.stderr)
        return 2

    print(f"{len(alarmlar)} SSH brute-force alarmı bulundu ({args.log})")
    hatali = 0
    for sira, alarm in enumerate(alarmlar, start=1):
        olay = alarmi_olaya_cevir(alarm, args.cihaz_adi.strip(), saat_dilimi)
        ozet = f"[{sira}] {olay['kaynak_ip']} ({alarm['deneme_sayisi']} deneme)"
        if args.kuru_calistirma:
            print(f"{ozet} gönderilmedi: {json.dumps(olay, ensure_ascii=False)}")
            continue
        try:
            durum, yanit = olay_gonder(args.api_url, api_anahtari, olay)
        except AjanHatasi as hata:
            print(f"{ozet} -> HATA: {hata}", file=sys.stderr)
            return 1  # API'ye hiç ulaşılamıyorsa diğer alarmları denemenin anlamı yok
        if durum in (200, 201):
            tur = "yeni olay" if yanit.get("yeni_olay") else "mevcut olay güncellendi"
            print(f"{ozet} -> HTTP {durum} {tur}, olay_id={yanit.get('olay_id')}, "
                  f"tekrar_sayisi={yanit.get('tekrar_sayisi')}")
        else:
            hatali += 1
            print(f"{ozet} -> HTTP {durum} {yanit.get('hata', '?')}: {yanit.get('mesaj', '')}")
    return 1 if hatali else 0


if __name__ == "__main__":
    sys.exit(main())
