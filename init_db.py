from sqlalchemy import create_engine, text

DATABASE_URI = "postgresql://sboreddy:12345678@localhost/cs595"

engine = create_engine(DATABASE_URI)

INIT_DB_SCRIPT = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS questions (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS answers (
    id SERIAL PRIMARY KEY,
    body TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    question_id INTEGER REFERENCES questions(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

with engine.connect() as connection:
    connection.execute(text(INIT_DB_SCRIPT))
    print("Database initialized!")