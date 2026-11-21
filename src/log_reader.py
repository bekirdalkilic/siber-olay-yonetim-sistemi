def read_log_lines(path):
    """Log dosyasını okur, boş olmayan her satırı sözlük olarak döndürür.

    path: log dosyasının yolu (str)
    Dönüş: [{"satir_no": 1, "ham": "..."}, ...]
    satir_no dosyadaki gerçek satır numarasıdır (boş satırlar da sayılır).
    Dosya yoksa FileNotFoundError yükselir, bilerek yakalamıyoruz.
    """
    satirlar = []
    satir_no = 0

    with open(path, encoding="utf-8") as f:
        for satir in f:
            satir_no += 1
            temiz = satir.strip()
            if temiz != "":
                satirlar.append({"satir_no": satir_no, "ham": temiz})

    return satirlar
