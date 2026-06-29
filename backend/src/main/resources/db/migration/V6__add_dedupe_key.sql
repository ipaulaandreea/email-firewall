ALTER TABLE emails ADD COLUMN dedupe_key VARCHAR(128);

ALTER TABLE emails ADD CONSTRAINT uk_email_dedupe UNIQUE(dedupe_key);