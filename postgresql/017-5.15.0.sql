-- #2623

ALTER TABLE usr_prp
ADD COLUMN lck_ste_nam varchar(1024),
ADD COLUMN lck_ste_dt int8;

INSERT INTO BLITZ_SCHEMA_VERSION (SCRIPT_NAME, DATE) VALUES ('017-5.15.0.sql', LOCALTIMESTAMP(2));
