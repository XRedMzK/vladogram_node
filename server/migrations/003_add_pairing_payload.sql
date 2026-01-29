ALTER TABLE pairings ADD COLUMN payload_ciphertext BLOB;
ALTER TABLE pairings ADD COLUMN payload_nonce BLOB;
ALTER TABLE pairings ADD COLUMN payload_meta TEXT;
ALTER TABLE pairings ADD COLUMN verify_code TEXT;
