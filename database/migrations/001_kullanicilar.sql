BEGIN;

CREATE TABLE public.kullanicilar (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kullanici_adi VARCHAR(50) NOT NULL UNIQUE,
    parola_hash TEXT NOT NULL,
    yetki SMALLINT NOT NULL,
    aktif_mi BOOLEAN NOT NULL DEFAULT TRUE,
    hatali_giris INTEGER NOT NULL DEFAULT 0,
    kilit_bitis TIMESTAMPTZ,

    CONSTRAINT kullanici_adi_bos_degil
        CHECK (btrim(kullanici_adi) <> ''),

    CONSTRAINT parola_argon2id
        CHECK (parola_hash LIKE '$argon2id$%'),

    CONSTRAINT yetki_kontrolu
        CHECK (yetki IN (0, 1)),

    CONSTRAINT hatali_giris_kontrolu
        CHECK (hatali_giris >= 0)
);

GRANT SELECT ON public.kullanicilar TO siber_api;

GRANT UPDATE (hatali_giris, kilit_bitis)
ON public.kullanicilar TO siber_api;

COMMIT;
