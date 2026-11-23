-- Güvenlik Duvarı Tabanlı Olay Yönetimi: PostgreSQL şeması
--
-- Çalıştırma (boş bir veritabanında):
--   psql -v ON_ERROR_STOP=1 -d <veritabani> -f database/schema.sql
-- Her şey tek işlemde (BEGIN/COMMIT) yapılır: hata çıkarsa hiçbir tablo kalmaz.

BEGIN;

-- Tek bir IP adresi. inet tipi IPv4 ve IPv6 tutar, geçersiz adresi reddeder.
-- CHECK, "10.0.0.0/8" gibi bir ağ aralığının girilmesini engeller:
-- maske uzunluğu adres uzunluğuna (IPv4: 32, IPv6: 128) eşit olmalı.
CREATE DOMAIN host_ip AS inet
    CHECK (masklen(VALUE) = CASE family(VALUE) WHEN 4 THEN 32 ELSE 128 END);

-- ---------------------------------------------------------------------------
-- cihazlar: izlenen cihazlar (ajanın çalıştığı makineler)
-- ---------------------------------------------------------------------------
CREATE TABLE cihazlar (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cihaz_adi           text    NOT NULL,
    ip_adresi           host_ip NOT NULL,
    kritiklik_seviyesi  text    NOT NULL DEFAULT 'orta',

    CONSTRAINT cihazlar_adi_benzersiz UNIQUE (cihaz_adi),
    CONSTRAINT cihazlar_ip_benzersiz  UNIQUE (ip_adresi),
    CONSTRAINT cihazlar_adi_bos_degil CHECK (btrim(cihaz_adi) <> ''),
    CONSTRAINT cihazlar_kritiklik_gecerli
        CHECK (kritiklik_seviyesi IN ('dusuk', 'orta', 'yuksek', 'kritik'))
);

-- ---------------------------------------------------------------------------
-- olaylar: tespit edilen olaylar (günlük tekilleştirilmiş)
--
-- fingerprint = SHA-256 (hex, 64 küçük harf) şu değerlerin birleşiminden:
--   cihaz_id | olay_turu | kaynak_ip | hedef_ip (NULL ise boş) | olay günü
-- Aynı gün aynı olay tekrar gelirse yeni satır açılmaz; UPSERT ile
-- tekrar_sayisi artırılır, ilk_gorulme/son_gorulme güncellenir.
-- ---------------------------------------------------------------------------
CREATE TABLE olaylar (
    id             bigint    GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cihaz_id       bigint   NOT NULL,   -- olayı gören cihaz (ajan yapılandırmasından bilinir)
    kaynak_ip      host_ip   NOT NULL,
    hedef_ip       host_ip,              -- NULL olabilir: SSH loglarında hedef IP yoktur
    olay_turu      text      NOT NULL,
    fingerprint    text      NOT NULL,
    tekrar_sayisi  integer   NOT NULL DEFAULT 1,
    ilk_gorulme    timestamptz NOT NULL,   -- tekilleştirilen olayın ilk görüldüğü zaman
    son_gorulme    timestamptz NOT NULL,   -- tekilleştirilen olayın son görüldüğü zaman
    olay_zamani    timestamptz NOT NULL,   -- satırı oluşturan ilk alarmın tespit zamanı

    CONSTRAINT olaylar_cihaz_fk
        FOREIGN KEY (cihaz_id) REFERENCES cihazlar (id) ON DELETE RESTRICT,
    CONSTRAINT olaylar_fingerprint_benzersiz UNIQUE (fingerprint),
    CONSTRAINT olaylar_fingerprint_sha256
        CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT olaylar_olay_turu_gecerli
        CHECK (olay_turu IN ('ssh_brute_force', 'port_scan')),
    CONSTRAINT olaylar_tekrar_pozitif
        CHECK (tekrar_sayisi >= 1),
    CONSTRAINT olaylar_zaman_sirasi
        CHECK (son_gorulme >= ilk_gorulme),
    CONSTRAINT olaylar_port_scan_hedef_zorunlu
        CHECK (olay_turu <> 'port_scan' OR hedef_ip IS NOT NULL)
);

-- Yabancı anahtar sütunu otomatik indekslenmez; cihaza göre sorgular için ekliyoruz.
CREATE INDEX olaylar_cihaz_id_idx ON olaylar (cihaz_id);

COMMIT;
