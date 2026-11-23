import json
import threading
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from werkzeug.serving import make_server

from src.api.app import create_app
from src.api.validation import olay_dogrula
from src.ssh_ajan import (
    AjanHatasi,
    alarmi_olaya_cevir,
    main,
    olay_gonder,
    ssh_alarmlari_bul,
    zaman_dilimi_coz,
)

VERI = Path(__file__).resolve().parents[1] / "data"
DEMO_LOG = str(VERI / "ssh_demo_bruteforce.log")
ORNEK_LOG = str(VERI / "ssh_sample.log")
ANAHTAR = "ajan-test-anahtari"
YANLIS_ANAHTAR = "yanlis-ajan-anahtari"
DB_ADRESI = "postgresql://kullanici:cok-gizli-sifre@localhost/test"
ISTANBUL = ZoneInfo("Europe/Istanbul")


# ---------- gerçek HTTP sunucusu (DB sahte) ----------

@pytest.fixture
def sunucu(monkeypatch):
    """Gerçek Flask uygulamasını gerçek bir HTTP portunda çalıştırır; sadece
    veritabanı katmanı (olay_isle) sahtedir. Ajan -> HTTP -> Flask yolu gerçektir.

    sunucu.olaylar: API'nin DB katmanına ilettiği olaylar.
    sunucu.cevap: istenirse (olay) -> (olay_id, tekrar_sayisi) ya da None döndüren fonksiyon.
    """
    durum = SimpleNamespace(olaylar=[], cevap=None, url=None)

    def sahte_olay_isle(database_url, olay):
        durum.olaylar.append(olay)
        if durum.cevap is not None:
            return durum.cevap(olay)
        return (len(durum.olaylar), 1)

    monkeypatch.setattr("src.api.app.olay_isle", sahte_olay_isle)
    app = create_app({"API_KEY": ANAHTAR, "DATABASE_URL": DB_ADRESI})
    srv = make_server("127.0.0.1", 0, app)
    # poll_interval kısa: shutdown() her testte yarım saniye beklemesin.
    kanal = threading.Thread(target=lambda: srv.serve_forever(poll_interval=0.02), daemon=True)
    kanal.start()
    durum.url = f"http://127.0.0.1:{srv.server_port}"
    yield durum
    srv.shutdown()
    kanal.join()


def ortam(**ekstra):
    o = {"API_KEY": ANAHTAR}
    o.update(ekstra)
    return o


def komut(sunucu, *ekstra):
    return ["--log", DEMO_LOG, "--yil", "2026", "--cihaz-adi", "demo-fw-01",
            "--saat-dilimi", "Europe/Istanbul", "--api-url", sunucu.url, *ekstra]


# ---------- ssh_alarmlari_bul ----------

def test_demo_logunda_iki_alarm_var():
    alarmlar = ssh_alarmlari_bul(DEMO_LOG, 2026)
    assert [a["kaynak_ip"] for a in alarmlar] == ["203.0.113.5", "192.0.2.77"]
    assert all(a["olay_turu"] == "ssh_brute_force" and a["deneme_sayisi"] == 6 for a in alarmlar)


def test_demo_logunda_esigin_altindaki_ip_alarm_vermez():
    ipler = [a["kaynak_ip"] for a in ssh_alarmlari_bul(DEMO_LOG, 2026)]
    assert "198.51.100.23" not in ipler   # 5 başarısız deneme
    assert "198.51.100.7" not in ipler    # başarılı giriş + publickey hatası


def test_eski_ornek_logda_alarm_yok():
    assert ssh_alarmlari_bul(ORNEK_LOG, 2026) == []


def test_log_dosyasi_yoksa_filenotfounderror():
    with pytest.raises(FileNotFoundError):
        ssh_alarmlari_bul(str(VERI / "yok.log"), 2026)


# ---------- zaman_dilimi_coz ----------

def test_zaman_dilimi_gecerli():
    assert zaman_dilimi_coz("Europe/Istanbul") == ISTANBUL
    assert zaman_dilimi_coz("  UTC ") == ZoneInfo("UTC")


@pytest.mark.parametrize("ad", [None, "", "   ", "Mars/Olympus", "../etc/passwd", "Europe"])
def test_zaman_dilimi_bos_ya_da_gecersizse_hata(ad):
    with pytest.raises(AjanHatasi):
        zaman_dilimi_coz(ad)


# ---------- alarmi_olaya_cevir ----------

ALARM = {
    "kaynak_ip": "203.0.113.5", "olay_turu": "ssh_brute_force",
    "deneme_sayisi": 6, "tespit_zamani": datetime(2026, 11, 24, 13, 58, 18),
}


def test_alarm_olaya_cevrilir_saat_dilimi_acikca_eklenir():
    olay = alarmi_olaya_cevir(ALARM, "demo-fw-01", ISTANBUL)
    assert olay == {
        "cihaz_adi": "demo-fw-01", "olay_turu": "ssh_brute_force",
        "kaynak_ip": "203.0.113.5", "olay_zamani": "2026-11-24T13:58:18+03:00",
    }


def test_verilen_saat_dilimi_sonucu_degistirir():
    utc = alarmi_olaya_cevir(ALARM, "demo-fw-01", ZoneInfo("UTC"))["olay_zamani"]
    ist = alarmi_olaya_cevir(ALARM, "demo-fw-01", ISTANBUL)["olay_zamani"]
    assert utc == "2026-11-24T13:58:18+00:00"
    assert utc != ist


def test_uretilen_json_api_dogrulamasindan_gecer():
    olay = alarmi_olaya_cevir(ALARM, "demo-fw-01", ISTANBUL)
    temiz, hatalar = olay_dogrula(olay)
    assert hatalar == {}
    assert temiz["hedef_ip"] is None   # SSH alarmında hedef IP yok


def test_zaten_saat_dilimli_alarm_reddedilir():
    alarm = dict(ALARM, tespit_zamani=ALARM["tespit_zamani"].replace(tzinfo=ISTANBUL))
    with pytest.raises(AjanHatasi):
        alarmi_olaya_cevir(alarm, "demo-fw-01", ISTANBUL)


# ---------- olay_gonder (gerçek HTTP) ----------

OLAY = alarmi_olaya_cevir(ALARM, "demo-fw-01", ISTANBUL)


def test_gonder_yeni_olay_201(sunucu):
    durum, govde = olay_gonder(sunucu.url, ANAHTAR, OLAY)
    assert durum == 201
    assert govde == {"olay_id": 1, "tekrar_sayisi": 1, "yeni_olay": True}


def test_gonder_tekrar_200(sunucu):
    sunucu.cevap = lambda olay: (1, 4)
    durum, govde = olay_gonder(sunucu.url, ANAHTAR, OLAY)
    assert (durum, govde["tekrar_sayisi"], govde["yeni_olay"]) == (200, 4, False)


def test_gonder_yanlis_anahtar_401_hata_firlatmaz(sunucu):
    durum, govde = olay_gonder(sunucu.url, YANLIS_ANAHTAR, OLAY)
    assert durum == 401
    assert govde["hata"] == "gecersiz_api_anahtari"
    assert sunucu.olaylar == []


def test_gonder_bilinmeyen_cihaz_422(sunucu):
    sunucu.cevap = lambda olay: None
    durum, govde = olay_gonder(sunucu.url, ANAHTAR, OLAY)
    assert (durum, govde["hata"]) == (422, "bilinmeyen_cihaz")


def test_gonder_sunucu_yoksa_ajanhatasi_anahtar_mesajda_yok():
    with pytest.raises(AjanHatasi) as hata:
        olay_gonder("http://127.0.0.1:1", ANAHTAR, OLAY, zaman_asimi=2)
    assert ANAHTAR not in str(hata.value)


@pytest.mark.parametrize("adres", ["file:///etc/passwd", "ftp://x", "127.0.0.1:5000", ""])
def test_gonder_http_olmayan_adres_reddedilir(adres):
    with pytest.raises(AjanHatasi):
        olay_gonder(adres, ANAHTAR, OLAY)


# ---------- main (komut satırı) ----------

def test_main_iki_alarmi_gonderir_201(sunucu, capsys):
    kod = main(komut(sunucu), ortam())
    cikti = capsys.readouterr().out
    assert kod == 0
    assert "2 SSH brute-force alarmı bulundu" in cikti
    assert cikti.count("HTTP 201 yeni olay") == 2
    assert [o["kaynak_ip"] for o in sunucu.olaylar] == ["203.0.113.5", "192.0.2.77"]
    assert [o["cihaz_adi"] for o in sunucu.olaylar] == ["demo-fw-01", "demo-fw-01"]


def test_main_zamanlar_istanbul_saat_diliminde_gonderilir(sunucu):
    main(komut(sunucu), ortam())
    ilk = sunucu.olaylar[0]["olay_zamani"]
    assert ilk.utcoffset() == timedelta(hours=3)
    assert ilk.isoformat() == "2026-11-24T13:58:18+03:00"


def test_main_baska_saat_dilimi_baska_ani_gonderir(sunucu):
    argv = komut(sunucu)
    argv[argv.index("Europe/Istanbul")] = "UTC"
    main(argv, ortam())
    assert sunucu.olaylar[0]["olay_zamani"].utcoffset() == timedelta(0)


def test_main_tekrar_eden_olay_200_mesaji(sunucu, capsys):
    sunucu.cevap = lambda olay: (5, 3)
    assert main(komut(sunucu), ortam()) == 0
    cikti = capsys.readouterr().out
    assert "HTTP 200 mevcut olay güncellendi, olay_id=5, tekrar_sayisi=3" in cikti


def test_main_yanlis_anahtar_cikis_1_anahtarlar_yazilmaz(sunucu, capsys):
    kod = main(komut(sunucu), ortam(API_KEY=YANLIS_ANAHTAR))
    kayit = capsys.readouterr()
    assert kod == 1
    assert "HTTP 401" in kayit.out
    for metin in (kayit.out, kayit.err):
        assert YANLIS_ANAHTAR not in metin
        assert ANAHTAR not in metin
    assert sunucu.olaylar == []


def test_main_bilinmeyen_cihaz_cikis_1(sunucu, capsys):
    sunucu.cevap = lambda olay: None
    assert main(komut(sunucu), ortam()) == 1
    assert "bilinmeyen_cihaz" in capsys.readouterr().out


def test_main_api_kapaliysa_cikis_1(capsys):
    argv = ["--log", DEMO_LOG, "--yil", "2026", "--cihaz-adi", "demo-fw-01",
            "--saat-dilimi", "Europe/Istanbul", "--api-url", "http://127.0.0.1:1"]
    assert main(argv, ortam()) == 1
    kayit = capsys.readouterr()
    assert "API'ye ulaşılamadı" in kayit.err
    assert ANAHTAR not in kayit.out + kayit.err


def test_main_kuru_calistirma_gondermez_ve_anahtar_istemez(sunucu, capsys):
    kod = main(komut(sunucu, "--kuru-calistirma"), {})   # API_KEY bile yok
    cikti = capsys.readouterr().out
    assert kod == 0
    assert sunucu.olaylar == []
    assert cikti.count("gönderilmedi") == 2
    assert "2026-11-24T13:58:18+03:00" in cikti


def test_main_ayarlar_ortam_degiskenlerinden_de_okunur(sunucu):
    argv = ["--log", DEMO_LOG, "--yil", "2026", "--api-url", sunucu.url]
    kod = main(argv, ortam(CIHAZ_ADI="demo-fw-01", LOG_SAAT_DILIMI="Europe/Istanbul"))
    assert kod == 0
    assert len(sunucu.olaylar) == 2


@pytest.mark.parametrize("silinecek, beklenen_mesaj", [
    ("--saat-dilimi", "saat dilimi"),
    ("--cihaz-adi", "Cihaz adı"),
])
def test_main_zorunlu_ayar_yoksa_hic_gondermez(sunucu, capsys, silinecek, beklenen_mesaj):
    argv = komut(sunucu)
    i = argv.index(silinecek)
    del argv[i:i + 2]
    assert main(argv, ortam()) == 2
    assert beklenen_mesaj in capsys.readouterr().err
    assert sunucu.olaylar == []


def test_main_api_anahtari_yoksa_hic_gondermez(sunucu, capsys):
    assert main(komut(sunucu), {}) == 2
    assert "API_KEY" in capsys.readouterr().err
    assert sunucu.olaylar == []


def test_main_log_yoksa_cikis_2(sunucu, capsys):
    argv = komut(sunucu)
    argv[argv.index(DEMO_LOG)] = str(VERI / "yok.log")
    assert main(argv, ortam()) == 2
    assert "bulunamadı" in capsys.readouterr().err


def test_main_yil_zorunlu(sunucu):
    argv = komut(sunucu)
    i = argv.index("--yil")
    del argv[i:i + 2]
    with pytest.raises(SystemExit) as cikis:   # argparse eksik bayrakta çıkış kodu 2 ile çıkar
        main(argv, ortam())
    assert cikis.value.code == 2
