-- =====================================================================
-- SecureCloud - Supabase-Native PostgreSQL Database Migration
-- Canonical Architecture: auth.users -> public.profiles -> resources
-- Implements Foreign Keys, Strict Cross-User Data Isolation, and Genuine RLS
-- =====================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. PUBLIC.PROFILES TABLE (References Supabase auth.users)
-- Supabase Auth is responsible for credential management and password hashing in auth.users.
-- public.profiles stores application-level profile data, storage metrics, and RBAC roles.
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(128) UNIQUE NOT NULL,
    role VARCHAR(32) DEFAULT 'USER' NOT NULL CHECK (role IN ('USER', 'ADMIN', 'SECURITY_ANALYST')),
    is_active BOOLEAN DEFAULT TRUE,
    is_2fa_enabled BOOLEAN DEFAULT FALSE,
    two_factor_enforced BOOLEAN DEFAULT FALSE,
    two_factor_code VARCHAR(16),
    two_factor_expires_at TIMESTAMP WITH TIME ZONE,
    totp_secret VARCHAR(64),
    quota_bytes BIGINT DEFAULT 10737418240, -- 10 GB standard quota
    used_quota_bytes BIGINT DEFAULT 0,
    is_locked_down BOOLEAN DEFAULT FALSE,
    risk_score FLOAT DEFAULT 0.0,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip VARCHAR(45) DEFAULT '127.0.0.1',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_profiles_username ON public.profiles(username);
CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);

-- Auto-provision Profile on Supabase auth.users insert
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, username, email, role)
    VALUES (
        NEW.id,
        COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1)),
        NEW.email,
        COALESCE(NEW.raw_app_meta_data->>'role', 'USER')
    )
    ON CONFLICT (id) DO UPDATE
    SET email = EXCLUDED.email,
        username = EXCLUDED.username;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Prevent Standard Users from elevating their own role to ADMIN or SECURITY_ANALYST
CREATE OR REPLACE FUNCTION public.prevent_self_role_elevation()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.role <> OLD.role THEN
        IF auth.uid() = OLD.id AND OLD.role NOT IN ('ADMIN', 'SECURITY_ANALYST') THEN
            RAISE EXCEPTION 'Access Denied: Standard users cannot elevate their own role to %', NEW.role;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS enforce_profile_role_protection ON public.profiles;
CREATE TRIGGER enforce_profile_role_protection
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.prevent_self_role_elevation();

-- Backward compatibility view for queries targeting "users"
CREATE OR REPLACE VIEW public.users AS SELECT * FROM public.profiles;

-- 3. USER SESSIONS TABLE
CREATE TABLE IF NOT EXISTS public.user_sessions (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) DEFAULT '127.0.0.1',
    user_agent VARCHAR(256) DEFAULT 'Browser',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON public.user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_revoked ON public.user_sessions(is_revoked);

-- 4. FILES TABLE
CREATE TABLE IF NOT EXISTS public.files (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    filename VARCHAR(256) NOT NULL,
    original_filename VARCHAR(256) NOT NULL,
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64) NOT NULL, -- SHA-256
    sha1_hash VARCHAR(40),
    md5_hash VARCHAR(32),
    mime_type VARCHAR(128) DEFAULT 'application/octet-stream',
    extension VARCHAR(32) DEFAULT '',
    storage_path TEXT NOT NULL,
    s3_key TEXT,
    is_confidential BOOLEAN DEFAULT FALSE,
    is_in_recycle_bin BOOLEAN DEFAULT FALSE,
    current_version VARCHAR(16) DEFAULT 'v1.0',
    threat_score FLOAT DEFAULT 0.0,
    security_status VARCHAR(32) DEFAULT 'CLEAN', -- CLEAN, LOW, SUSPICIOUS, HIGH, MALICIOUS, CRITICAL, QUARANTINED
    is_quarantined BOOLEAN DEFAULT FALSE,
    quarantine_reason TEXT,
    last_scanned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_files_user_id ON public.files(user_id);
CREATE INDEX IF NOT EXISTS idx_files_hash ON public.files(file_hash);
CREATE INDEX IF NOT EXISTS idx_files_status ON public.files(security_status);
CREATE INDEX IF NOT EXISTS idx_files_quarantine ON public.files(is_quarantined);

-- 5. FILE VERSIONS TABLE
CREATE TABLE IF NOT EXISTS public.file_versions (
    id SERIAL PRIMARY KEY,
    file_id VARCHAR(36) NOT NULL REFERENCES public.files(id) ON DELETE CASCADE,
    version_tag VARCHAR(16) NOT NULL,
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    storage_path TEXT NOT NULL,
    uploader_id UUID NOT NULL REFERENCES public.profiles(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_versions_file_id ON public.file_versions(file_id);

-- 6. SECURITY SCANS (Multi-layer scan records)
CREATE TABLE IF NOT EXISTS public.security_scans (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    file_id VARCHAR(36) NOT NULL REFERENCES public.files(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    file_hash VARCHAR(64) NOT NULL,
    threat_score FLOAT DEFAULT 0.0,
    final_verdict VARCHAR(64) DEFAULT 'CLEAN',
    security_status VARCHAR(32) DEFAULT 'CLEAN',
    ml_prediction VARCHAR(32) DEFAULT 'CLEAN',
    ml_probabilities JSONB DEFAULT '{}'::jsonb,
    model_version VARCHAR(32) DEFAULT 'LightGBM-v2.1',
    heuristic_score FLOAT DEFAULT 0.0,
    heuristic_verdict VARCHAR(32) DEFAULT 'CLEAN',
    triggered_rules JSONB DEFAULT '[]'::jsonb,
    explanations JSONB DEFAULT '[]'::jsonb,
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_file ON public.security_scans(file_id);
CREATE INDEX IF NOT EXISTS idx_scans_user ON public.security_scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON public.security_scans(final_verdict);

-- 7. SECURITY EVENTS (SOC Telemetry Stream)
CREATE TABLE IF NOT EXISTS public.security_events (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    event_type VARCHAR(64) NOT NULL,
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    file_id VARCHAR(36),
    file_hash VARCHAR(64),
    ip_address VARCHAR(45) DEFAULT '127.0.0.1',
    user_agent VARCHAR(256),
    severity VARCHAR(32) DEFAULT 'INFO', -- INFO, LOW, MEDIUM, HIGH, CRITICAL
    result VARCHAR(32) DEFAULT 'SUCCESS', -- SUCCESS, FAILED, BLOCKED
    metadata JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_type ON public.security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON public.security_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_created ON public.security_events(timestamp DESC);

-- 8. SECURITY INCIDENTS (Sentinel Application-Level Incidents)
CREATE TABLE IF NOT EXISTS public.security_incidents (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    incident_type VARCHAR(64) NOT NULL,
    severity VARCHAR(32) DEFAULT 'HIGH',
    status VARCHAR(32) DEFAULT 'ACTIVE', -- ACTIVE, CONTAINED, RESOLVED, FALSE_POSITIVE
    title VARCHAR(256) NOT NULL,
    description TEXT,
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    file_id VARCHAR(36),
    ip_address VARCHAR(45),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by VARCHAR(64),
    mitigation_actions JSONB DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON public.security_incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON public.security_incidents(severity);

-- 9. SHARED LINKS (Secure cryptographically-random tokens with revocations)
CREATE TABLE IF NOT EXISTS public.shared_links (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    file_id VARCHAR(36) NOT NULL REFERENCES public.files(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    token VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(256),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    max_downloads INT DEFAULT 0,
    access_count INT DEFAULT 0,
    last_accessed_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_shared_token ON public.shared_links(token);
CREATE INDEX IF NOT EXISTS idx_shared_file ON public.shared_links(file_id);
CREATE INDEX IF NOT EXISTS idx_shared_user ON public.shared_links(user_id);

-- 10. AUDIT LOGS
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    action VARCHAR(64) NOT NULL,
    target VARCHAR(256) NOT NULL,
    status VARCHAR(32) DEFAULT 'SUCCESS',
    details TEXT,
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    username VARCHAR(64),
    role VARCHAR(32),
    ip_address VARCHAR(45),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON public.audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON public.audit_logs(user_id);

-- 11. QUARANTINE FILES
CREATE TABLE IF NOT EXISTS public.quarantine_files (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    file_id VARCHAR(36) REFERENCES public.files(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    file_hash VARCHAR(64),
    original_filename VARCHAR(256),
    quarantine_path TEXT NOT NULL,
    quarantined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    reason TEXT,
    status VARCHAR(32) DEFAULT 'QUARANTINED'
);

CREATE INDEX IF NOT EXISTS idx_quarantine_file ON public.quarantine_files(file_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_user ON public.quarantine_files(user_id);

-- 12. IP RULES (Firewall Guard)
CREATE TABLE IF NOT EXISTS public.ip_rules (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    rule_type VARCHAR(16) DEFAULT 'BLACKLIST', -- BLACKLIST, WHITELIST
    description VARCHAR(256),
    threat_status VARCHAR(32) DEFAULT 'MALICIOUS',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_ip_rules_address ON public.ip_rules(ip_address);

-- =====================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- Zero cross-user data leakage guarantee
-- =====================================================================

-- Helper: Check if active user has Administrator or Security Analyst role
CREATE OR REPLACE FUNCTION public.is_admin_or_analyst()
RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = auth.uid() AND role IN ('ADMIN', 'SECURITY_ANALYST')
    );
$$ LANGUAGE sql SECURITY DEFINER STABLE;

-- Enable RLS on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.files ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.file_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.shared_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quarantine_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ip_rules ENABLE ROW LEVEL SECURITY;

-- 1. Profiles RLS: Users can view/update own profile; Admins can view all
CREATE POLICY profiles_select_policy ON public.profiles
    FOR SELECT USING (id = auth.uid() OR public.is_admin_or_analyst());

CREATE POLICY profiles_update_policy ON public.profiles
    FOR UPDATE USING (id = auth.uid() OR public.is_admin_or_analyst());

-- 2. Files RLS: Strict cross-user isolation. Non-admins cannot read quarantined files.
CREATE POLICY files_select_policy ON public.files
    FOR SELECT USING (
        (user_id = auth.uid() AND is_quarantined = FALSE)
        OR public.is_admin_or_analyst()
    );

CREATE POLICY files_insert_policy ON public.files
    FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE POLICY files_update_policy ON public.files
    FOR UPDATE USING (user_id = auth.uid() OR public.is_admin_or_analyst());

CREATE POLICY files_delete_policy ON public.files
    FOR DELETE USING (user_id = auth.uid() OR public.is_admin_or_analyst());

-- 3. File Versions RLS: Accessible only by owning user or Admin
CREATE POLICY versions_select_policy ON public.file_versions
    FOR SELECT USING (
        EXISTS (SELECT 1 FROM public.files WHERE files.id = file_versions.file_id AND files.user_id = auth.uid())
        OR public.is_admin_or_analyst()
    );

CREATE POLICY versions_insert_policy ON public.file_versions
    FOR INSERT WITH CHECK (
        EXISTS (SELECT 1 FROM public.files WHERE files.id = file_versions.file_id AND files.user_id = auth.uid())
        OR public.is_admin_or_analyst()
    );

-- 4. Shared Links RLS: Only owner or admin can view/manage private share links
CREATE POLICY shares_select_policy ON public.shared_links
    FOR SELECT USING (user_id = auth.uid() OR public.is_admin_or_analyst());

CREATE POLICY shares_insert_policy ON public.shared_links
    FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE POLICY shares_update_policy ON public.shared_links
    FOR UPDATE USING (user_id = auth.uid() OR public.is_admin_or_analyst());

CREATE POLICY shares_delete_policy ON public.shared_links
    FOR DELETE USING (user_id = auth.uid() OR public.is_admin_or_analyst());

-- 5. Security Scans RLS: User can see own scans; Admin can see all
CREATE POLICY scans_select_policy ON public.security_scans
    FOR SELECT USING (user_id = auth.uid() OR public.is_admin_or_analyst());

-- 6. Quarantine Files RLS: Non-admins are strictly blocked from quarantine records
CREATE POLICY quarantine_admin_only_policy ON public.quarantine_files
    FOR ALL USING (public.is_admin_or_analyst());

-- 7. Audit Logs & Telemetry RLS: Admin only
CREATE POLICY audit_admin_only ON public.audit_logs
    FOR ALL USING (public.is_admin_or_analyst());

CREATE POLICY events_admin_only ON public.security_events
    FOR ALL USING (public.is_admin_or_analyst());

CREATE POLICY incidents_admin_only ON public.security_incidents
    FOR ALL USING (public.is_admin_or_analyst());

CREATE POLICY ip_rules_admin_only ON public.ip_rules
    FOR ALL USING (public.is_admin_or_analyst());
