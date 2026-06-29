ALTER TABLE emails
    ADD COLUMN owner_username VARCHAR(320);

ALTER TABLE emails
    ALTER COLUMN owner_username SET NOT NULL;