-- =====================================================================
-- SecureCloud - Supabase PostgreSQL Database Migration Script
-- Production-Ready Schema with Foreign Keys, Indexes, and RLS Policies
-- =====================================================================

-- 1. USERS & PROFILES TABLE
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(128) UNIQUE NOT NULL,
    hashed_password VARCHAR(256) NOT NULL,
    role VARCHAR(32) DEFAULT 'USER' NOT NULL, -- 'USER', 'ADMIN', 'SECURITY_ANALYST'
    is_active BOOLEAN DEFAULT TRUE,
    is_2fa_enabled BOOLEAN DEFAULT FALSE,
    two_factor_enforced BOOLEAN DEFAULT FALSE,
    two_factor_code VARCHAR(16),
    two_factor_expires_at TIMESTAMP WITH TIME ZONE,
    totp_secret VARCHAR(64),
    reset_token VARCHAR(64),
    reset_token_expiry TIMESTAMP WITH TIME ZONE,
    quota_bytes BIGINT DEFAULT 10737418240, -- 10 GB
    used_quota_bytes BIGINT DEFAULT 0,
    admin_security_code VARCHAR(32),
    is_locked_down BOOLEAN DEFAULT FALSE,
    risk_score FLOAT DEFAULT 0.0,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- 2. USER SESSIONS
CREATE TABLE IF NOT EXISTS user_sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) DEFAULT '127.0.0.1',
    user_agent VARCHAR(256) DEFAULT 'Browser',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_revoked ON user_sessions(is_revoked);

-- 3. FILES TABLE
CREATE TABLE IF NOT EXISTS files (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename VARCHAR(256) NOT NULL,
    original_filename VARCHAR(256) NOT NULL,
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64) NOT NULL, -- SHA-256
    sha1_hash VARCHAR(40),
    md5_hash VARCHAR(32),
    mime_type VARCHAR(128) DEFAULT 'application/octet-stream',
    extension VARCHAR(32) DEFAULT '',
    storage_path TEXT,
    s3_key TEXT,
    is_confidential BOOLEAN DEFAULT FALSE,
    is_in_recycle_bin BOOLEAN DEFAULT FALSE,
    current_version VARCHAR(16) DEFAULT 'v1.0',
    threat_score FLOAT DEFAULT 0.0,
    security_status VARCHAR(32) DEFAULT 'CLEAN', -- 'CLEAN', 'LOW RISK', 'SUSPICIOUS', 'HIGH RISK', 'MALICIOUS', 'QUARANTINED'
    is_quarantined BOOLEAN DEFAULT FALSE,
    quarantine_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);
CREATE INDEX IF NOT EXISTS idx_files_hash ON files(file_hash);
CREATE INDEX IF NOT EXISTS idx_files_status ON files(security_status);
CREATE INDEX IF NOT EXISTS idx_files_quarantine ON files(is_quarantined);

-- 4. FILE VERSIONS
CREATE TABLE IF NOT EXISTS file_versions (
    id VARCHAR(36) PRIMARY KEY,
    file_id VARCHAR(36) NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    version_number VARCHAR(16) NOT NULL,
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    mime_type VARCHAR(128) DEFAULT 'application/octet-stream',
    storage_path TEXT,
    s3_key TEXT,
    threat_score FLOAT DEFAULT 0.0,
    security_verdict VARCHAR(32) DEFAULT 'CLEAN',
    uploaded_by_user_id INT REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_versions_file_id ON file_versions(file_id);

-- 5. SECURITY SCANS (Comprehensive multi-layer records)
CREATE TABLE IF NOT EXISTS security_scans (
    id VARCHAR(36) PRIMARY KEY,
    file_id VARCHAR(36) NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id INT REFERENCES users(id),
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    scanner_status VARCHAR(64) DEFAULT 'COMPLETED',
    ml_status VARCHAR(64) DEFAULT 'READY',
    threat_score FLOAT DEFAULT 0.0,
    risk_level VARCHAR(32) DEFAULT 'CLEAN',
    detected_indicators JSONB DEFAULT '[]'::jsonb,
    final_verdict VARCHAR(64) DEFAULT 'CLEAN',
    quarantine_status VARCHAR(32) DEFAULT 'NONE',
    model_version VARCHAR(32) DEFAULT 'LightGBM-v2.1',
    scan_duration_ms INT DEFAULT 0,
    scan_layers JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_scans_file ON security_scans(file_id);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON security_scans(final_verdict);

-- 6. SECURITY EVENTS (SOC Telemetry & Audit Stream)
CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(36) PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    user_id INT REFERENCES users(id),
    ip_address VARCHAR(45) DEFAULT '127.0.0.1',
    user_agent VARCHAR(256),
    severity VARCHAR(32) DEFAULT 'INFO', -- 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    result VARCHAR(32) DEFAULT 'SUCCESS', -- 'SUCCESS', 'FAILED', 'BLOCKED'
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_created ON security_events(created_at DESC);

-- 7. INCIDENTS (Application-Level Incident Response)
CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(36) PRIMARY KEY,
    incident_type VARCHAR(64) NOT NULL,
    severity VARCHAR(32) DEFAULT 'HIGH',
    status VARCHAR(32) DEFAULT 'ACTIVE', -- 'ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'
    title VARCHAR(256) NOT NULL,
    description TEXT,
    user_id INT REFERENCES users(id),
    file_id VARCHAR(36) REFERENCES files(id),
    ip_address VARCHAR(45),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by VARCHAR(64),
    mitigation_actions JSONB DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

-- 8. SHARED LINKS (Secure cryptographically-random tokens with revocations)
CREATE TABLE IF NOT EXISTS shared_links (
    id VARCHAR(36) PRIMARY KEY,
    file_id VARCHAR(36) NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(256),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    max_downloads INT DEFAULT 0, -- 0 = unlimited
    access_count INT DEFAULT 0,
    last_accessed_at TIMESTAMP WITH TIME ZONE,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_shared_token ON shared_links(token);
CREATE INDEX IF NOT EXISTS idx_shared_file ON shared_links(file_id);

-- 9. AUDIT LOGS
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    action VARCHAR(64) NOT NULL,
    target VARCHAR(256) NOT NULL,
    status VARCHAR(32) DEFAULT 'SUCCESS',
    details TEXT,
    user_id INT REFERENCES users(id),
    username VARCHAR(64),
    role VARCHAR(32),
    ip_address VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);

-- 10. QUARANTINE RECORDS
CREATE TABLE IF NOT EXISTS quarantine_records (
    id VARCHAR(36) PRIMARY KEY,
    file_id VARCHAR(36) REFERENCES files(id) ON DELETE CASCADE,
    user_id INT REFERENCES users(id),
    original_path TEXT,
    quarantine_path TEXT,
    threat_verdict VARCHAR(64),
    threat_score FLOAT,
    reason TEXT,
    is_restored BOOLEAN DEFAULT FALSE,
    restored_at TIMESTAMP WITH TIME ZONE,
    restored_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_quarantine_file ON quarantine_records(file_id);

-- 11. IP RULES (Firewall Guard)
CREATE TABLE IF NOT EXISTS ip_rules (
    id VARCHAR(36) PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    rule_type VARCHAR(16) DEFAULT 'BLACKLIST', -- 'BLACKLIST', 'WHITELIST'
    reason VARCHAR(256),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_ip_rules_address ON ip_rules(ip_address);

-- =====================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- =====================================================================

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE files ENABLE ROW LEVEL SECURITY;
ALTER TABLE file_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE shared_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE quarantine_records ENABLE ROW LEVEL SECURITY;

-- File Access: Tenants can view and manage their own non-quarantined files
CREATE POLICY tenant_files_isolation ON files
    FOR ALL
    USING (
        auth.uid()::text = user_id::text 
        OR EXISTS (SELECT 1 FROM users WHERE users.id::text = auth.uid()::text AND users.role IN ('ADMIN', 'SECURITY_ANALYST'))
    );

-- Quarantine Access: Non-admins cannot download or select quarantined files
CREATE POLICY quarantine_protection ON files
    FOR SELECT
    USING (
        is_quarantined = FALSE
        OR EXISTS (SELECT 1 FROM users WHERE users.id::text = auth.uid()::text AND users.role IN ('ADMIN', 'SECURITY_ANALYST'))
    );

-- Versions Isolation
CREATE POLICY tenant_versions_isolation ON file_versions
    FOR ALL
    USING (
        EXISTS (SELECT 1 FROM files WHERE files.id = file_versions.file_id AND (files.user_id::text = auth.uid()::text))
        OR EXISTS (SELECT 1 FROM users WHERE users.id::text = auth.uid()::text AND users.role IN ('ADMIN', 'SECURITY_ANALYST'))
    );

-- Share Links Isolation
CREATE POLICY tenant_shares_isolation ON shared_links
    FOR ALL
    USING (
        user_id::text = auth.uid()::text
        OR EXISTS (SELECT 1 FROM users WHERE users.id::text = auth.uid()::text AND users.role IN ('ADMIN', 'SECURITY_ANALYST'))
    );
