CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
                       id UUID PRIMARY KEY,
                       email VARCHAR(255) NOT NULL UNIQUE,
                       password_hash VARCHAR(255) NOT NULL,
                       role VARCHAR(50) NOT NULL,
                       created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE TABLE emails (
                        id UUID PRIMARY KEY,
                        ingest_source VARCHAR(50) NOT NULL,
                        received_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),

                        from_address VARCHAR(255) NOT NULL,
                        from_domain VARCHAR(255),
                        reply_to VARCHAR(255),

                        subject TEXT,
                        message_id VARCHAR(255) UNIQUE,

                        body_text TEXT,
                        body_html_sanitized TEXT,
                        size_bytes BIGINT,

                        threat_score INTEGER NOT NULL DEFAULT 0,
                        verdict VARCHAR(50) NOT NULL,
                        status VARCHAR(50) NOT NULL
);

CREATE INDEX idx_emails_received_at ON emails(received_at);
CREATE INDEX idx_emails_verdict ON emails(verdict);
CREATE INDEX idx_emails_score ON emails(threat_score);

CREATE TABLE email_recipients (
                                  email_id UUID NOT NULL,
                                  recipient VARCHAR(255) NOT NULL,
                                  CONSTRAINT fk_email_recipients
                                      FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);
CREATE INDEX idx_recipients_email ON email_recipients(email_id);

CREATE TABLE email_headers (
                               id BIGSERIAL PRIMARY KEY,
                               email_id UUID NOT NULL,
                               name VARCHAR(255) NOT NULL,
                               value TEXT,
                               CONSTRAINT fk_email_headers
                                   FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);
CREATE INDEX idx_headers_email ON email_headers(email_id);
CREATE INDEX idx_headers_name ON email_headers(name);

CREATE TABLE auth_results (
                              id BIGSERIAL PRIMARY KEY,
                              email_id UUID NOT NULL UNIQUE,

                              spf_result VARCHAR(50),
                              dkim_result VARCHAR(50),
                              dmarc_result VARCHAR(50),
                              dmarc_policy VARCHAR(50),

                              details_json JSONB,

                              CONSTRAINT fk_auth_results_email
                                  FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);
CREATE INDEX idx_auth_email ON auth_results(email_id);

CREATE TABLE email_links (
                             id BIGSERIAL PRIMARY KEY,
                             email_id UUID NOT NULL,

                             url_raw TEXT NOT NULL,
                             url_normalized TEXT,
                             host VARCHAR(255),
                             is_shortener BOOLEAN NOT NULL DEFAULT FALSE,
                             verdict VARCHAR(50),

                             CONSTRAINT fk_email_links
                                 FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);
CREATE INDEX idx_links_email ON email_links(email_id);
CREATE INDEX idx_links_host ON email_links(host);

CREATE TABLE link_signals (
                              id BIGSERIAL PRIMARY KEY,
                              link_id BIGINT NOT NULL,

                              signal_type VARCHAR(100),
                              severity VARCHAR(50),
                              score_delta INTEGER,
                              details TEXT,

                              CONSTRAINT fk_link_signals
                                  FOREIGN KEY (link_id) REFERENCES email_links(id) ON DELETE CASCADE
);
CREATE INDEX idx_signals_link ON link_signals(link_id);

CREATE TABLE email_attachments (
                                   id BIGSERIAL PRIMARY KEY,
                                   email_id UUID NOT NULL,

                                   filename VARCHAR(512),
                                   content_type VARCHAR(255),
                                   size_bytes BIGINT,
                                   sha256 VARCHAR(64),
                                   extension VARCHAR(32),
                                   verdict VARCHAR(50),

                                   CONSTRAINT fk_email_attachments
                                       FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);
CREATE INDEX idx_attach_email ON email_attachments(email_id);
CREATE INDEX idx_attach_sha ON email_attachments(sha256);

CREATE TABLE rules (
                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                       name VARCHAR(255) NOT NULL,

                       type VARCHAR(50) NOT NULL,
                       target VARCHAR(50) NOT NULL,
                       pattern TEXT,

                       action VARCHAR(50) NOT NULL,
                       score_delta INTEGER,
                       verdict VARCHAR(50),

                       enabled BOOLEAN NOT NULL DEFAULT TRUE,
                       priority INTEGER NOT NULL DEFAULT 100,
                       updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX idx_rules_enabled ON rules(enabled);
CREATE INDEX idx_rules_priority ON rules(priority);

CREATE TABLE rule_hits (
                           id BIGSERIAL PRIMARY KEY,
                           email_id UUID NOT NULL,
                           rule_id UUID NOT NULL,

                           hit_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                           score_delta INTEGER,
                           message TEXT,

                           CONSTRAINT fk_rule_hits_email
                               FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE,
                           CONSTRAINT fk_rule_hits_rule
                               FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
);

CREATE INDEX idx_rulehits_email ON rule_hits(email_id);
CREATE INDEX idx_rulehits_rule ON rule_hits(rule_id);

CREATE TABLE audit_events (
                              id BIGSERIAL PRIMARY KEY,
                              event_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                              actor_user_id UUID,

                              entity_type VARCHAR(50) NOT NULL,
                              entity_id VARCHAR(255) NOT NULL,
                              action VARCHAR(50) NOT NULL,

                              details_json JSONB,

                              CONSTRAINT fk_audit_actor
                                  FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_audit_time ON audit_events(event_at);
CREATE INDEX idx_audit_entity ON audit_events(entity_type, entity_id);
