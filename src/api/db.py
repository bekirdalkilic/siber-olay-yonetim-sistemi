import hashlib
from datetime import timezone

import psycopg

# Her iki sorguda da değerler %s ile AYRI gönderilir (parametreli sorgu):
# psycopg değeri SQL metnine yapıştırmaz, bu yüzden SQL injection olmaz.

# Cihaz adından id bulur. cihaz_adi UNIQUE olduğu için en fazla 1 satır döner.
CIHAZ_SORGUSU = "SELECT id FROM cihazlar WHERE cihaz_adi = %s"

# "Yoksa ekle, varsa güncelle" (upsert).
#  - ON CONFLICT (fingerprint): bu fingerprint zaten tabloda varsa hata verme...
#  - DO UPDATE: ...bunun yerine mevcut satırı güncelle.
#  - EXCLUDED: eklemeye çalıştığımız yeni satır; olaylar.xxx: tablodaki mevcut satır.
#  - LEAST/GREATEST: ilk_gorulme en erken, son_gorulme en geç zamanı korur.
#  - RETURNING: eklenen/güncellenen satırın id ve tekrar_sayisi'ni geri verir.
# Güncellenen sütunlar siber_api rolünün UPDATE yetkisi olan 3 sütunla sınırlıdır.
OLAY_SORGUSU = """
INSERT INTO olaylar
    (cihaz_id, kaynak_ip, hedef_ip, olay_turu, fingerprint,
     ilk_gorulme, son_gorulme, olay_zamani)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (fingerprint) DO UPDATE SET
    tekrar_sayisi = olaylar.tekrar_sayisi + 1,
    ilk_gorulme   = LEAST(olaylar.ilk_gorulme, EXCLUDED.ilk_gorulme),
    son_gorulme   = GREATEST(olaylar.son_gorulme, EXCLUDED.son_gorulme)
RETURNING id, tekrar_sayisi
"""


def parmak_izi_uret(cihaz_id, olay_turu, kaynak_ip, hedef_ip, olay_zamani):
    """Olayın günlük parmak izini (SHA-256, 64 küçük harfli hex) üretir.

    cihaz_id: olayı gören cihazın veritabanı numarası (int).
    olay_turu: "ssh_brute_force" ya da "port_scan".
    kaynak_ip: normalize edilmiş IP metni (olay_dogrula'dan gelir).
    hedef_ip: IP metni ya da None (SSH'ta olmayabilir; boş metin olarak katılır).
    olay_zamani: saat dilimli datetime. Gün, UTC'ye çevrilerek bulunur; böylece
        aynı anı farklı saat dilimleriyle gönderen iki istek aynı güne düşer.
    """
    gun = olay_zamani.astimezone(timezone.utc).date().isoformat()
    parcalar = [str(cihaz_id), olay_turu, kaynak_ip, hedef_ip or "", gun]
    return hashlib.sha256("|".join(parcalar).encode("utf-8")).hexdigest()


def cihaz_id_bul(cur, cihaz_adi):
    """cihaz_adi'na karşılık gelen cihaz id'sini döndürür; kayıtlı değilse None.

    cur: açık bir psycopg cursor'ı (SQL'i çalıştıran nesne).
    """
    cur.execute(CIHAZ_SORGUSU, (cihaz_adi,))
    satir = cur.fetchone()  # tek satır (id,) ya da hiç satır yoksa None
    if satir is None:
        return None
    return satir[0]


def olay_kaydet(cur, cihaz_id, olay):
    """Olayı ekler ya da (aynı parmak izi varsa) günceller; (olay_id, tekrar_sayisi) döner.

    cur: açık cursor. cihaz_id: cihaz_id_bul'dan gelen numara.
    olay: olay_dogrula'nın temiz sözlüğü (zamanlar saat dilimli datetime).
    """
    parmak_izi = parmak_izi_uret(
        cihaz_id,
        olay["olay_turu"],
        olay["kaynak_ip"],
        olay["hedef_ip"],
        olay["olay_zamani"],
    )
    cur.execute(
        OLAY_SORGUSU,
        (
            cihaz_id,
            olay["kaynak_ip"],
            olay["hedef_ip"],
            olay["olay_turu"],
            parmak_izi,
            olay["ilk_gorulme"],
            olay["olay_zamani"],  # son_gorulme: yeni olayda olay zamanıdır
            olay["olay_zamani"],
        ),
    )
    return cur.fetchone()


def olay_isle(database_url, olay):
    """Cihazı bulup olayı kaydeder. (olay_id, tekrar_sayisi) döner; cihaz yoksa None.

    database_url: bağlantı adresi. Parola URL içinde olabilir ya da boş bırakılıp
        libpq'nun ~/.pgpass dosyasından okunabilir. Hiçbir yere yazdırılmaz.
    olay: olay_dogrula'nın temiz sözlüğü.

    Transaction: "with psycopg.connect(...)" bloğu hatasız biterse COMMIT eder,
    içeride hata çıkarsa ROLLBACK eder (yarım kayıt kalmaz) ve bağlantıyı kapatır.
    Bağlantı/veritabanı hataları psycopg.Error olarak yukarı (app.py'ye) fırlar.
    """
    with psycopg.connect(database_url, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cihaz_id = cihaz_id_bul(cur, olay["cihaz_adi"])
            if cihaz_id is None:
                return None
            return olay_kaydet(cur, cihaz_id, olay)
