CREATE EXTENSION IF NOT EXISTS "pgcrypto";

INSERT INTO users (id, email, password_hash, role)
SELECT gen_random_uuid(),
       'admin@example.com',
       '$2a$12$X81bwyQ2T3Pj/QW6SIJosuT964EKX7L79FrBtPpYPQM8Ugr0kOy1y',
       'ADMIN'
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin@example.com');

INSERT INTO users (id, email, password_hash, role)
SELECT gen_random_uuid(),
       'analyst@example.com',
       '$2a$12$X81bwyQ2T3Pj/QW6SIJosuT964EKX7L79FrBtPpYPQM8Ugr0kOy1y',
       'ANALYST'
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'analyst@example.com');

INSERT INTO users (id, email, password_hash, role)
SELECT gen_random_uuid(),
       'dev@example.com',
       '$2a$12$X81bwyQ2T3Pj/QW6SIJosuT964EKX7L79FrBtPpYPQM8Ugr0kOy1y',
       'DEVELOPER'
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'dev@example.com');