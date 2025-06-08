-- Удаляем индекс
DROP INDEX IF EXISTS idx_users_phone;

-- Удаляем добавленные колонки
ALTER TABLE users
DROP COLUMN IF EXISTS phone,
DROP COLUMN IF EXISTS verified;