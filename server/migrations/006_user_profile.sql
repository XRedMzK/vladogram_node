ALTER TABLE users ADD COLUMN display_name TEXT;
ALTER TABLE users ADD COLUMN avatar_url TEXT;

UPDATE users
SET display_name = nickname
WHERE display_name IS NULL;
