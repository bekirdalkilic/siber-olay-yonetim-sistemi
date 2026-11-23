import pytest

from src.api.app import create_app
from src.api.config import AyarHatasi

TEST_AYARLARI = {"API_KEY": "test-anahtari", "DATABASE_URL": "postgresql://test@localhost/test"}


@pytest.fixture
def istemci():
    """Her test için sahte ayarlarla yeni bir Flask test istemcisi verir."""
    return create_app(TEST_AYARLARI).test_client()


def test_health_200_ve_json_doner(istemci):
    yanit = istemci.get("/health")

    assert yanit.status_code == 200
    assert yanit.get_json() == {"status": "ok"}


def test_health_post_kabul_etmez(istemci):
    # /health yalnızca GET'tir: POST gönderilirse 405 Method Not Allowed.
    assert istemci.post("/health").status_code == 405


def test_olmayan_yol_404_doner(istemci):
    assert istemci.get("/yok").status_code == 404


def test_uygulama_ayarlari_ortam_degiskenlerinden_alir(monkeypatch):
    monkeypatch.setenv("API_KEY", "ortamdan-gelen-anahtar")
    monkeypatch.setenv("DATABASE_URL", "postgresql://siber_api@localhost/siber_olay_yonetimi")

    app = create_app()

    assert app.config["API_KEY"] == "ortamdan-gelen-anahtar"
    assert app.config["DATABASE_URL"] == "postgresql://siber_api@localhost/siber_olay_yonetimi"


def test_ortam_degiskenleri_yoksa_uygulama_baslamaz(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(AyarHatasi):
        create_app()
