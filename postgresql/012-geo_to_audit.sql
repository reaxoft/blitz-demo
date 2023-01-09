-- IB-2479: add geo data to audit

ALTER TABLE AUD
ADD COLUMN IP_CTR VARCHAR(128),
ADD COLUMN IP_ST VARCHAR(128),
ADD COLUMN IP_CT VARCHAR(128),
ADD COLUMN IP_LAT DOUBLE PRECISION,
ADD COLUMN IP_LNG DOUBLE PRECISION,
ADD COLUMN IP_RAD INTEGER;