from pathlib import Path

import pytest

from src.log_reader import read_log_lines

# Bu test dosyasının iki üst klasörü proje köküdür; oradan data/ içine iniyoruz.
ORNEK_LOG = Path(__file__).resolve().parent.parent / "data" / "ssh_sample.log"


def test_dort_kayit_ve_gercek_satir_numaralari():
    sonuc = read_log_lines(ORNEK_LOG)

    assert len(sonuc) == 4
    assert [kayit["satir_no"] for kayit in sonuc] == [1, 2, 4, 5]


def test_kayit_bicimi_ve_temiz_metin():
    sonuc = read_log_lines(ORNEK_LOG)
    ilk = sonuc[0]

    assert set(ilk.keys()) == {"satir_no", "ham"}
    assert ilk["ham"].startswith("Nov 21 10:15:01")
    assert not ilk["ham"].endswith("\n")


def test_dosya_yoksa_hata_gizlenmez(tmp_path):
    olmayan_dosya = tmp_path / "yok.log"

    with pytest.raises(FileNotFoundError):
        read_log_lines(olmayan_dosya)
