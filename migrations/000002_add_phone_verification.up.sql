-- Добавляем новые поля в таблицу users
ALTER TABLE users
    ADD COLUMN phone VARCHAR(20),
ADD COLUMN verified BOOLEAN DEFAULT FALSE;

-- Создаем индекс для быстрого поиска по телефону
CREATE INDEX idx_users_phone ON users(phone);