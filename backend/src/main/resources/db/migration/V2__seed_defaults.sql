INSERT INTO users (id, email, password_hash, role)
VALUES (
           gen_random_uuid(),
           'admin@example.com',
           '$2a$12$X81bwyQ2T3Pj/QW6SIJosuT964EKX7L79FrBtPpYPQM8Ugr0kOy1y',
           'ADMIN'
       );

INSERT INTO rules (name, type, target, pattern, action, verdict, enabled, priority)
VALUES (
           'Blacklist sender domain evil.com',
           'BLACKLIST',
           'SENDER_DOMAIN',
           'evil.com',
           'SET_VERDICT',
           'BLOCK',
           TRUE,
           10
       );

INSERT INTO rules (name, type, target, pattern, action, score_delta, enabled, priority)
VALUES (
           'Subject contains urgent/invoice/payment (+30)',
           'REGEX',
           'SUBJECT',
           '(?i)urgent|invoice|payment',
           'ADD_SCORE',
           30,
           TRUE,
           50
       );

INSERT INTO rules (name, type, target, pattern, action, verdict, enabled, priority)
VALUES (
           'Block dangerous attachment extensions',
           'ATTACHMENT',
           'ATTACHMENT_EXT',
           'exe,js,iso',
           'SET_VERDICT',
           'BLOCK',
           TRUE,
           20
       );
