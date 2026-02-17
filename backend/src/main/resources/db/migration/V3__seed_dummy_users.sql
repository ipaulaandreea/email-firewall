-- DEV ONLY credentials:
-- admin@example.com / Admin123!
-- analyst@example.com / Analyst123!
-- dev@example.com / Dev123!

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

INSERT INTO users (id, email, password_hash, role)
SELECT gen_random_uuid(),
       'admin@example.com',
       '$2a$12$eNnPtSM50KMm5ETi5eZWeehmtffflQZNLEiuMvFFNG7SnYveNwkuW',
       'ADMIN'
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin@example.com');

INSERT INTO users (id, email, password_hash, role)
SELECT gen_random_uuid(),
       'analyst@example.com',
       '$2a$12$bFOlMRYMGHKBBwBirCUfr.bR.oRAIERnF7ziGWyqYOY0joWXpDzKG',
       'ANALYST'
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'analyst@example.com');

INSERT INTO users (id, email, password_hash, role)
SELECT gen_random_uuid(),
       'dev@example.com',
       '$2a$12$xLOxBOrfVZMJvtfjYrI.8etwAIEbI8z2vkYc6YNjQCnbZ.B59kJGa',
       'DEVELOPER'
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'dev@example.com');