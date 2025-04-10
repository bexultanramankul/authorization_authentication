CREATE TABLE users (
                       id UUID PRIMARY KEY,
                       email VARCHAR(255) UNIQUE NOT NULL,
                       password_hash VARCHAR(255) NOT NULL,
                       created_at TIMESTAMP DEFAULT NOW(),
                       updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE sessions (
                          id UUID PRIMARY KEY,
                          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                          refresh_token TEXT NOT NULL,
                          expires_at TIMESTAMP NOT NULL,
                          created_at TIMESTAMP DEFAULT NOW(),
                          user_agent TEXT,
                          ip VARCHAR(45),
                          is_revoked BOOLEAN DEFAULT FALSE,
                          UNIQUE (refresh_token)
);

-- Индексы для быстрого поиска
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);