-- Plugin Schema Extensions for Better-Auth-like functionality

-- Two-Factor Authentication
CREATE TABLE IF NOT EXISTS "two_factor" (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    backup_codes TEXT, -- JSON array of hashed backup codes
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id)
);

-- Trusted Devices (for 2FA)
CREATE TABLE IF NOT EXISTS "trusted_device" (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_trusted_device_user ON "trusted_device"(user_id);
CREATE INDEX idx_trusted_device_device ON "trusted_device"(device_id);

-- Passkeys (WebAuthn)
CREATE TABLE IF NOT EXISTS "passkey" (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    device_type TEXT, -- "platform" or "cross-platform"
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    transports TEXT, -- JSON array
    aaguid TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_passkey_user ON "passkey"(user_id);
CREATE INDEX idx_passkey_credential ON "passkey"(credential_id);

-- Organizations
CREATE TABLE IF NOT EXISTS "organization" (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    logo TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_organization_slug ON "organization"(slug);

-- Organization Members
CREATE TABLE IF NOT EXISTS "member" (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    organization_id TEXT NOT NULL REFERENCES "organization"(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, organization_id)
);

CREATE INDEX idx_member_user ON "member"(user_id);
CREATE INDEX idx_member_org ON "member"(organization_id);

-- Organization Invitations
CREATE TABLE IF NOT EXISTS "invitation" (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES "organization"(id) ON DELETE CASCADE,
    inviter_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    status TEXT NOT NULL DEFAULT 'pending', -- pending, accepted, rejected, cancelled
    team_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invitation_email ON "invitation"(email);
CREATE INDEX idx_invitation_org ON "invitation"(organization_id);
CREATE INDEX idx_invitation_status ON "invitation"(status);

-- Teams (optional, for organizations)
CREATE TABLE IF NOT EXISTS "team" (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES "organization"(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_team_org ON "team"(organization_id);

-- Team Members
CREATE TABLE IF NOT EXISTS "team_member" (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES "team"(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(team_id, user_id)
);

CREATE INDEX idx_team_member_team ON "team_member"(team_id);
CREATE INDEX idx_team_member_user ON "team_member"(user_id);

-- Organization Roles (for dynamic RBAC)
CREATE TABLE IF NOT EXISTS "organization_role" (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES "organization"(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    permissions JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, role)
);

CREATE INDEX idx_org_role_org ON "organization_role"(organization_id);

-- User extensions for admin features
ALTER TABLE "user" ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';
ALTER TABLE "user" ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT FALSE;
ALTER TABLE "user" ADD COLUMN IF NOT EXISTS ban_reason TEXT;
ALTER TABLE "user" ADD COLUMN IF NOT EXISTS ban_expires TIMESTAMPTZ;

-- Session extensions for organization context
ALTER TABLE "session" ADD COLUMN IF NOT EXISTS active_organization_id TEXT REFERENCES "organization"(id) ON DELETE SET NULL;
ALTER TABLE "session" ADD COLUMN IF NOT EXISTS active_team_id TEXT REFERENCES "team"(id) ON DELETE SET NULL;
ALTER TABLE "session" ADD COLUMN IF NOT EXISTS impersonated_by TEXT REFERENCES "user"(id) ON DELETE SET NULL;
