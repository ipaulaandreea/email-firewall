# Email Firewall

A rule-based email security system built with Spring Boot and React.

This project analyzes incoming emails, applies configurable security rules, calculates a threat score, and assigns a final verdict: **ALLOW**, **QUARANTINE**, or **BLOCK**.

---

## Tech Stack

### Backend
- Spring Boot 3
- Spring Data JPA
- PostgreSQL
- Flyway (database migrations)

### Frontend
- React
- REST API integration

### Optional
- Spring Boot Actuator
- Prometheus
- Grafana

---

## Core Features

### Email Ingestion

- `POST /api/ingest/json`
- Persists emails in the database
- Automatically evaluates rules
- Computes threat score and verdict

---

### Rule Engine

Configurable rules stored in the database.

#### Supported Rule Types
- BLACKLIST
- WHITELIST
- REGEX
- KEYWORD
- ATTACHMENT

#### Rule Actions
- ADD_SCORE
- SET_VERDICT
- BYPASS

---

### Scoring & Verdict

- Each email receives a cumulative threat score.
- Score thresholds determine:
    - ALLOW
    - QUARANTINE
    - BLOCK

---

### Authentication Signals

Stores and evaluates:
- SPF
- DKIM
- DMARC

---

### URL & Attachment Analysis

- URL extraction
- Attachment extension validation
- SHA-256 hashing

---

### Audit Logging

Tracks:
- Rule changes
- Email processing
- Quarantine actions

---

## Database Management

- Schema versioning is handled using Flyway migrations.

---

## Flowchart


```mermaid

flowchart TD
A[Ingest<br/>EML Upload / JSON / IMAP] --> B[Persist raw email<br/>emails.status=RECEIVED]
B --> C[Parse MIME<br/>headers/body/attachments]
C --> D[Extract artifacts<br/>links + attachment hashes]
D --> E[Checks<br/>SPF / DKIM / DMARC]
D --> F[URL heuristics<br/>punycode, shortener, IP-in-URL, mismatch]
C --> G[Policy engine<br/>whitelist/blacklist/regex/attachments]
E --> H[Scoring engine<br/>aggregate signals -> 0..100]
F --> H
G --> H
H --> I[Verdict<br/>ALLOW / QUARANTINE / BLOCK]
I --> J[Persist results<br/>auth_results, rule_hits, reasons]
I --> K{Quarantine?}
K -- yes --> L[Quarantine store + actions<br/>release/delete/false positive]
K -- no --> M[Allow/Block outcome<br/>status updated]
J --> N[Metrics + Logs<br/>Prometheus/Grafana]
L --> N
M --> N

```