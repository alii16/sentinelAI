-- ============================================================
-- SENTINEL AI - DATABASE SCHEMA
-- Autonomous Multi-Agent AI Security Auditor
-- Version 1.0
-- Engine: MySQL 8 InnoDB
-- ============================================================

CREATE DATABASE IF NOT EXISTS sentinel_ai
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE sentinel_ai;

SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================
-- TABLE 1: roles
-- ============================================================
CREATE TABLE IF NOT EXISTS roles (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255),
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ============================================================
-- TABLE 2: users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    role_id      BIGINT UNSIGNED NOT NULL,
    name         VARCHAR(150) NOT NULL,
    email        VARCHAR(255) NOT NULL UNIQUE,
    password     VARCHAR(255) NOT NULL,
    avatar       VARCHAR(500),
    is_active    TINYINT(1) NOT NULL DEFAULT 1,
    last_login   TIMESTAMP NULL,
    deleted_at   TIMESTAMP NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles(id)
) ENGINE=InnoDB;

CREATE INDEX idx_users_email    ON users(email);
CREATE INDEX idx_users_role_id  ON users(role_id);
CREATE INDEX idx_users_deleted  ON users(deleted_at);

-- ============================================================
-- TABLE 3: websites
-- ============================================================
CREATE TABLE IF NOT EXISTS websites (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id       BIGINT UNSIGNED NOT NULL,
    name          VARCHAR(150) NOT NULL,
    url           VARCHAR(500) NOT NULL,
    domain        VARCHAR(255),
    category      VARCHAR(100),
    description   TEXT,
    status        ENUM('active','inactive','suspended') NOT NULL DEFAULT 'active',
    last_scan_at  TIMESTAMP NULL,
    deleted_at    TIMESTAMP NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_websites_user FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE INDEX idx_websites_user_id ON websites(user_id);
CREATE INDEX idx_websites_deleted ON websites(deleted_at);

-- ============================================================
-- TABLE 4: scans
-- ============================================================
CREATE TABLE IF NOT EXISTS scans (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    website_id       BIGINT UNSIGNED NOT NULL,
    user_id          BIGINT UNSIGNED NOT NULL,
    mode             ENUM('quick','standard','full') NOT NULL DEFAULT 'standard',
    status           ENUM('pending','running','paused','completed','cancelled','failed') NOT NULL DEFAULT 'pending',
    max_depth        INT NOT NULL DEFAULT 5,
    max_pages        INT NOT NULL DEFAULT 1000,
    timeout_ms       INT NOT NULL DEFAULT 10000,
    security_score   DECIMAL(5,2),
    grade            CHAR(1),
    risk_level       ENUM('critical','high','medium','low','safe'),
    total_pages      INT NOT NULL DEFAULT 0,
    total_endpoints  INT NOT NULL DEFAULT 0,
    total_findings   INT NOT NULL DEFAULT 0,
    critical_count   INT NOT NULL DEFAULT 0,
    high_count       INT NOT NULL DEFAULT 0,
    medium_count     INT NOT NULL DEFAULT 0,
    low_count        INT NOT NULL DEFAULT 0,
    started_at       TIMESTAMP NULL,
    completed_at     TIMESTAMP NULL,
    duration_seconds INT,
    error_message    TEXT,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_scans_website FOREIGN KEY (website_id) REFERENCES websites(id),
    CONSTRAINT fk_scans_user    FOREIGN KEY (user_id)    REFERENCES users(id)
) ENGINE=InnoDB;

CREATE INDEX idx_scans_website_id ON scans(website_id);
CREATE INDEX idx_scans_user_id    ON scans(user_id);
CREATE INDEX idx_scans_status     ON scans(status);

-- ============================================================
-- TABLE 5: scan_logs
-- ============================================================
CREATE TABLE IF NOT EXISTS scan_logs (
    id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id    BIGINT UNSIGNED NOT NULL,
    level      ENUM('info','warning','error','debug') NOT NULL DEFAULT 'info',
    agent      VARCHAR(100),
    message    TEXT NOT NULL,
    metadata   JSON,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scan_logs_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_scan_logs_scan_id ON scan_logs(scan_id);

-- ============================================================
-- TABLE 6: pages
-- ============================================================
CREATE TABLE IF NOT EXISTS pages (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id         BIGINT UNSIGNED NOT NULL,
    url             VARCHAR(2000) NOT NULL,
    title           VARCHAR(500),
    status_code     SMALLINT,
    response_time   INT COMMENT 'ms',
    content_length  INT,
    content_type    VARCHAR(200),
    depth           INT NOT NULL DEFAULT 0,
    has_form        TINYINT(1) NOT NULL DEFAULT 0,
    has_login       TINYINT(1) NOT NULL DEFAULT 0,
    has_upload      TINYINT(1) NOT NULL DEFAULT 0,
    screenshot_path VARCHAR(500),
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_pages_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_pages_scan_id ON pages(scan_id);

-- ============================================================
-- TABLE 7: forms
-- ============================================================
CREATE TABLE IF NOT EXISTS forms (
    id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    page_id        BIGINT UNSIGNED NOT NULL,
    scan_id        BIGINT UNSIGNED NOT NULL,
    action         VARCHAR(1000),
    method         ENUM('GET','POST','PUT','PATCH','DELETE') NOT NULL DEFAULT 'POST',
    has_password   TINYINT(1) NOT NULL DEFAULT 0,
    has_file       TINYINT(1) NOT NULL DEFAULT 0,
    has_hidden     TINYINT(1) NOT NULL DEFAULT 0,
    input_count    INT NOT NULL DEFAULT 0,
    form_type      VARCHAR(100) COMMENT 'login,register,search,upload,comment,forgot,reset,contact',
    raw_html       MEDIUMTEXT,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_forms_page FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE,
    CONSTRAINT fk_forms_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_forms_page_id ON forms(page_id);
CREATE INDEX idx_forms_scan_id ON forms(scan_id);

-- ============================================================
-- TABLE 8: endpoints
-- ============================================================
CREATE TABLE IF NOT EXISTS endpoints (
    id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id        BIGINT UNSIGNED NOT NULL,
    url            VARCHAR(2000) NOT NULL,
    method         ENUM('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS') NOT NULL DEFAULT 'GET',
    endpoint_type  ENUM('page','api','static','form','redirect') NOT NULL DEFAULT 'page',
    priority_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
    has_auth       TINYINT(1) NOT NULL DEFAULT 0,
    has_params     TINYINT(1) NOT NULL DEFAULT 0,
    param_count    INT NOT NULL DEFAULT 0,
    status_code    SMALLINT,
    response_time  INT,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_endpoints_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_endpoints_scan_id       ON endpoints(scan_id);
CREATE INDEX idx_endpoints_priority      ON endpoints(priority_score DESC);

-- ============================================================
-- TABLE 9: technologies
-- ============================================================
CREATE TABLE IF NOT EXISTS technologies (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id     BIGINT UNSIGNED NOT NULL,
    name        VARCHAR(150) NOT NULL,
    version     VARCHAR(100),
    category    VARCHAR(100) COMMENT 'framework,cms,server,library,language,cdn,waf,database',
    confidence  TINYINT UNSIGNED NOT NULL DEFAULT 0,
    source      VARCHAR(100) COMMENT 'header,cookie,meta,html,js,css',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_technologies_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_technologies_scan_id ON technologies(scan_id);

-- ============================================================
-- TABLE 10: headers
-- ============================================================
CREATE TABLE IF NOT EXISTS headers (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id      BIGINT UNSIGNED NOT NULL,
    page_id      BIGINT UNSIGNED,
    header_name  VARCHAR(255) NOT NULL,
    header_value TEXT,
    is_security  TINYINT(1) NOT NULL DEFAULT 0,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_headers_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    CONSTRAINT fk_headers_page FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE INDEX idx_headers_scan_id ON headers(scan_id);

-- ============================================================
-- TABLE 11: cookies
-- ============================================================
CREATE TABLE IF NOT EXISTS cookies (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id     BIGINT UNSIGNED NOT NULL,
    name        VARCHAR(255) NOT NULL,
    value       TEXT,
    domain      VARCHAR(255),
    path        VARCHAR(500),
    http_only   TINYINT(1) NOT NULL DEFAULT 0,
    secure      TINYINT(1) NOT NULL DEFAULT 0,
    same_site   VARCHAR(20),
    expires     TIMESTAMP NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_cookies_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_cookies_scan_id ON cookies(scan_id);

-- ============================================================
-- TABLE 12: ml_models
-- ============================================================
CREATE TABLE IF NOT EXISTS ml_models (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name             VARCHAR(150) NOT NULL,
    algorithm        ENUM('random_forest','xgboost','decision_tree','svm') NOT NULL,
    version          VARCHAR(50) NOT NULL DEFAULT '1.0',
    file_path        VARCHAR(500),
    accuracy         DECIMAL(6,4),
    precision_score  DECIMAL(6,4),
    recall_score     DECIMAL(6,4),
    f1_score         DECIMAL(6,4),
    roc_auc          DECIMAL(6,4),
    training_time    DECIMAL(10,3) COMMENT 'seconds',
    sample_count     INT,
    feature_count    INT,
    is_active        TINYINT(1) NOT NULL DEFAULT 0,
    status           ENUM('training','ready','failed','archived') NOT NULL DEFAULT 'ready',
    trained_at       TIMESTAMP NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ============================================================
-- TABLE 13: datasets
-- ============================================================
CREATE TABLE IF NOT EXISTS datasets (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id      BIGINT UNSIGNED NOT NULL,
    name         VARCHAR(255) NOT NULL,
    description  TEXT,
    file_path    VARCHAR(500),
    file_size    BIGINT,
    sample_count INT,
    version      VARCHAR(50) NOT NULL DEFAULT '1.0',
    status       ENUM('pending','processing','ready','failed') NOT NULL DEFAULT 'pending',
    deleted_at   TIMESTAMP NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_datasets_user FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

-- ============================================================
-- TABLE 14: ai_predictions
-- ============================================================
CREATE TABLE IF NOT EXISTS ai_predictions (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id         BIGINT UNSIGNED NOT NULL,
    endpoint_id     BIGINT UNSIGNED,
    ml_model_id     BIGINT UNSIGNED,
    prediction      VARCHAR(150) NOT NULL,
    confidence      DECIMAL(5,2) NOT NULL DEFAULT 0,
    probability     JSON COMMENT 'class probabilities',
    severity        ENUM('critical','high','medium','low','info') NOT NULL DEFAULT 'info',
    owasp_category  VARCHAR(100),
    cwe_id          VARCHAR(50),
    is_verified     TINYINT(1) NOT NULL DEFAULT 0,
    is_false_positive TINYINT(1) NOT NULL DEFAULT 0,
    evidence        JSON,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_predictions_scan     FOREIGN KEY (scan_id)     REFERENCES scans(id) ON DELETE CASCADE,
    CONSTRAINT fk_predictions_endpoint FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE SET NULL,
    CONSTRAINT fk_predictions_model    FOREIGN KEY (ml_model_id) REFERENCES ml_models(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE INDEX idx_predictions_scan_id ON ai_predictions(scan_id);
CREATE INDEX idx_predictions_severity ON ai_predictions(severity);

-- ============================================================
-- TABLE 15: recommendations
-- ============================================================
CREATE TABLE IF NOT EXISTS recommendations (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id         BIGINT UNSIGNED NOT NULL,
    prediction_id   BIGINT UNSIGNED,
    title           VARCHAR(500) NOT NULL,
    summary         TEXT,
    cause           TEXT,
    impact          TEXT,
    solution        TEXT,
    priority        ENUM('critical','high','medium','low') NOT NULL DEFAULT 'medium',
    owasp_ref       VARCHAR(100),
    cwe_ref         VARCHAR(100),
    cvss_score      DECIMAL(4,2),
    affected_url    VARCHAR(2000),
    checklist       JSON,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_recommendations_scan       FOREIGN KEY (scan_id)       REFERENCES scans(id) ON DELETE CASCADE,
    CONSTRAINT fk_recommendations_prediction FOREIGN KEY (prediction_id) REFERENCES ai_predictions(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE INDEX idx_recommendations_scan_id  ON recommendations(scan_id);
CREATE INDEX idx_recommendations_priority ON recommendations(priority);

-- ============================================================
-- TABLE 16: reports
-- ============================================================
CREATE TABLE IF NOT EXISTS reports (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id          BIGINT UNSIGNED NOT NULL,
    user_id          BIGINT UNSIGNED NOT NULL,
    title            VARCHAR(500),
    pdf_path         VARCHAR(500),
    json_path        VARCHAR(500),
    csv_path         VARCHAR(500),
    executive_summary TEXT,
    security_score   DECIMAL(5,2),
    grade            CHAR(1),
    risk_level       ENUM('critical','high','medium','low','safe'),
    generated_at     TIMESTAMP NULL,
    deleted_at       TIMESTAMP NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_reports_scan FOREIGN KEY (scan_id) REFERENCES scans(id),
    CONSTRAINT fk_reports_user FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE INDEX idx_reports_scan_id ON reports(scan_id);
CREATE INDEX idx_reports_user_id ON reports(user_id);

-- ============================================================
-- TABLE 17: ai_chat_sessions
-- ============================================================
CREATE TABLE IF NOT EXISTS ai_chat_sessions (
    id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT UNSIGNED NOT NULL,
    scan_id    BIGINT UNSIGNED,
    title      VARCHAR(255) NOT NULL DEFAULT 'Sesi Baru',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_chat_sessions_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_chat_sessions_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ============================================================
-- TABLE 18: ai_chat_messages
-- ============================================================
CREATE TABLE IF NOT EXISTS ai_chat_messages (
    id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    session_id BIGINT UNSIGNED NOT NULL,
    role       ENUM('user','assistant') NOT NULL,
    content    MEDIUMTEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_chat_messages_session FOREIGN KEY (session_id) REFERENCES ai_chat_sessions(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_chat_messages_session ON ai_chat_messages(session_id);

-- ============================================================
-- TABLE 19: ai_memory
-- ============================================================
CREATE TABLE IF NOT EXISTS ai_memory (
    id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    website_id     BIGINT UNSIGNED NOT NULL,
    scan_id        BIGINT UNSIGNED NOT NULL,
    security_score DECIMAL(5,2),
    grade          CHAR(1),
    risk_level     VARCHAR(20),
    total_findings INT NOT NULL DEFAULT 0,
    critical_count INT NOT NULL DEFAULT 0,
    high_count     INT NOT NULL DEFAULT 0,
    medium_count   INT NOT NULL DEFAULT 0,
    low_count      INT NOT NULL DEFAULT 0,
    technologies   JSON,
    top_risks      JSON,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_ai_memory_website FOREIGN KEY (website_id) REFERENCES websites(id),
    CONSTRAINT fk_ai_memory_scan    FOREIGN KEY (scan_id)    REFERENCES scans(id)
) ENGINE=InnoDB;

CREATE INDEX idx_ai_memory_website ON ai_memory(website_id);

-- ============================================================
-- TABLE 20: activity_logs
-- ============================================================
CREATE TABLE IF NOT EXISTS activity_logs (
    id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT UNSIGNED,
    action     VARCHAR(150) NOT NULL,
    entity     VARCHAR(100),
    entity_id  BIGINT UNSIGNED,
    ip_address VARCHAR(50),
    user_agent TEXT,
    metadata   JSON,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_activity_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE INDEX idx_activity_user_id  ON activity_logs(user_id);
CREATE INDEX idx_activity_action   ON activity_logs(action);
CREATE INDEX idx_activity_created  ON activity_logs(created_at);

-- ============================================================
-- TABLE 21: notifications
-- ============================================================
CREATE TABLE IF NOT EXISTS notifications (
    id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT UNSIGNED NOT NULL,
    type       VARCHAR(100) NOT NULL,
    title      VARCHAR(255) NOT NULL,
    body       TEXT,
    data       JSON,
    is_read    TINYINT(1) NOT NULL DEFAULT 0,
    read_at    TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_notifications_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_notifications_is_read ON notifications(is_read);

-- ============================================================
-- TABLE 22: settings
-- ============================================================
CREATE TABLE IF NOT EXISTS settings (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    key_name    VARCHAR(150) NOT NULL UNIQUE,
    value       TEXT,
    type        ENUM('string','integer','boolean','json') NOT NULL DEFAULT 'string',
    group_name  VARCHAR(100),
    description VARCHAR(500),
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ============================================================
-- TABLE 23: scan_queue
-- ============================================================
CREATE TABLE IF NOT EXISTS scan_queue (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id     BIGINT UNSIGNED NOT NULL,
    status      ENUM('pending','running','waiting','completed','failed','cancelled') NOT NULL DEFAULT 'pending',
    priority    TINYINT UNSIGNED NOT NULL DEFAULT 5,
    attempts    TINYINT UNSIGNED NOT NULL DEFAULT 0,
    max_attempts TINYINT UNSIGNED NOT NULL DEFAULT 3,
    payload     JSON,
    error       TEXT,
    started_at  TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_queue_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_queue_status ON scan_queue(status);

-- ============================================================
-- TABLE 24: scan_progress
-- ============================================================
CREATE TABLE IF NOT EXISTS scan_progress (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id         BIGINT UNSIGNED NOT NULL UNIQUE,
    current_agent   VARCHAR(100),
    percentage      TINYINT UNSIGNED NOT NULL DEFAULT 0,
    discovery_pct   TINYINT UNSIGNED NOT NULL DEFAULT 0,
    technology_pct  TINYINT UNSIGNED NOT NULL DEFAULT 0,
    endpoint_pct    TINYINT UNSIGNED NOT NULL DEFAULT 0,
    scanner_pct     TINYINT UNSIGNED NOT NULL DEFAULT 0,
    verification_pct TINYINT UNSIGNED NOT NULL DEFAULT 0,
    report_pct      TINYINT UNSIGNED NOT NULL DEFAULT 0,
    pages_found     INT NOT NULL DEFAULT 0,
    endpoints_found INT NOT NULL DEFAULT 0,
    requests_sent   INT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_progress_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB;

SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================
-- SEED DATA
-- ============================================================

-- Default Roles
INSERT INTO roles (name, description) VALUES
    ('admin',   'Administrator dengan akses penuh'),
    ('analyst', 'Analis keamanan'),
    ('user',    'Pengguna umum');

-- Default Users (passwords are hashed using bcrypt)
INSERT INTO users (role_id, name, email, password) VALUES
    (1, 'Administrator', 'admin@gmail.com', '$2b$12$BWTx6lGHBZ6Giw6./Ulyq.nJesUJKES0Gg539Ok8/XhoMOlG3MTma'),
    (2, 'Jane Doe', 'analis@gmail.com', '$2b$12$qHRrwNdFknpG7tReNQ9njuE6QFG8ETfpsEMOKnIQurkFvRhKkYDki'),
    (3, 'John Doe', 'user@gmail.com', '$2b$12$0cxOF7RoUslIZezNl.RoKO35/ehUwhHT.ACWc/fqZViTL7J2JBG9q');

-- Default Settings
INSERT INTO settings (key_name, value, type, group_name, description) VALUES
    ('app_name',           'Sentinel AI',      'string',  'general',  'Nama aplikasi'),
    ('max_scan_depth',     '5',                'integer', 'scanner',  'Kedalaman crawling maksimum'),
    ('max_scan_pages',     '1000',             'integer', 'scanner',  'Jumlah halaman maksimum per scan'),
    ('scan_timeout_ms',    '10000',            'integer', 'scanner',  'Timeout request dalam ms'),
    ('scan_retry',         '2',                'integer', 'scanner',  'Jumlah retry per request'),
    ('scan_workers',       '5',                'integer', 'scanner',  'Jumlah worker paralel'),
    ('scan_delay_ms',      '100',              'integer', 'scanner',  'Delay antar request dalam ms'),
    ('rate_limit_rps',     '5',                'integer', 'scanner',  'Request per detik'),
    ('ai_model_active',    'random_forest',    'string',  'ai',       'Model ML yang aktif'),
    ('ai_confidence_min',  '50',               'integer', 'ai',       'Confidence minimum untuk laporan (%)'),
    ('report_path',        'reports/',         'string',  'report',   'Path penyimpanan laporan'),
    ('screenshot_enabled', '1',                'boolean', 'scanner',  'Aktifkan screenshot halaman');

-- Default ML Model records (placeholder)
INSERT INTO ml_models (name, algorithm, version, accuracy, precision_score, recall_score, f1_score, roc_auc, is_active, status) VALUES
    ('Random Forest v1.0',   'random_forest',  '1.0', 0.9540, 0.9510, 0.9480, 0.9495, 0.9820, 1, 'ready'),
    ('XGBoost v1.0',         'xgboost',        '1.0', 0.9620, 0.9590, 0.9560, 0.9575, 0.9880, 0, 'ready'),
    ('Decision Tree v1.0',   'decision_tree',  '1.0', 0.9120, 0.9080, 0.9050, 0.9065, 0.9300, 0, 'ready'),
    ('SVM v1.0',             'svm',            '1.0', 0.9350, 0.9310, 0.9280, 0.9295, 0.9650, 0, 'ready');
