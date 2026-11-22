CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('ADMIN', 'CUSTOMER')),
    email_verified INTEGER NOT NULL DEFAULT 0,
    account_status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (account_status IN ('ACTIVE', 'SUSPENDED')),
    mfa_secret_enc TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    recovery_codes_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS customer_profiles (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    customer_id TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    organization TEXT,
    organization_type TEXT NOT NULL,
    country TEXT NOT NULL,
    state TEXT NOT NULL,
    district TEXT NOT NULL,
    city TEXT NOT NULL,
    region TEXT NOT NULL,
    address TEXT NOT NULL,
    avatar_url TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_profiles (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    owner_title TEXT NOT NULL DEFAULT 'Founder' CHECK (owner_title IN ('Founder', 'Co-founder')),
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('VERIFY_EMAIL', 'RESET_PASSWORD')),
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    csrf_hash TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS test_records (
    id TEXT PRIMARY KEY,
    customer_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    sample_reference TEXT,
    sample_type TEXT NOT NULL,
    collected_at TEXT,
    country TEXT NOT NULL,
    state TEXT NOT NULL,
    district TEXT NOT NULL,
    city TEXT NOT NULL,
    region TEXT NOT NULL,
    address TEXT,
    latitude REAL,
    longitude REAL,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    detection_json TEXT,
    model_info TEXT,
    report_id TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    test_id TEXT NOT NULL REFERENCES test_records(id) ON DELETE CASCADE,
    customer_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'READY', 'FAILED')),
    storage_key TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    created_at TEXT NOT NULL,
    previous_hash TEXT,
    entry_hash TEXT
);
CREATE TABLE IF NOT EXISTS audit_chain_head (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    latest_hash TEXT NOT NULL DEFAULT '',
    latest_created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_profiles_geo ON customer_profiles(country, state, district, city, region);
CREATE INDEX IF NOT EXISTS idx_tests_customer_created ON test_records(customer_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tests_geo_created ON test_records(country, state, district, city, region, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tests_status_created ON test_records(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_owner_created ON reports(customer_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_user_expires ON sessions(user_id, expires_at);
