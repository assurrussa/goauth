-- Session-bound OIDC is an additive, isolated profile. Never infer a binding
-- for legacy rows. Migration requires a coordinated restart of all writers.
ALTER TABLE auth_oidc_refresh_families
    ADD COLUMN session_id TEXT,
    ADD COLUMN authorization_stamp TEXT,
    ADD COLUMN absolute_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT auth_oidc_family_binding_check CHECK (
        (session_id IS NULL AND authorization_stamp IS NULL AND absolute_expires_at IS NULL)
        OR (session_id IS NOT NULL AND authorization_stamp IS NOT NULL AND absolute_expires_at IS NOT NULL
            AND octet_length(session_id) BETWEEN 1 AND 256
            AND octet_length(authorization_stamp) BETWEEN 1 AND 192
            AND expires_at = absolute_expires_at AND created_at < expires_at
            AND authenticated_at <= created_at AND absolute_expires_at <= authenticated_at + interval '168 hours'));

CREATE TABLE auth_oidc_authorization_requests (
    selector TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    secret_digest BYTEA NOT NULL CHECK (octet_length(secret_digest) = 32),
    client_id TEXT NOT NULL,
    client_revision BIGINT NOT NULL CHECK (client_revision > 0),
    redirect_uri TEXT NOT NULL,
    state TEXT NOT NULL,
    nonce TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL CHECK (code_challenge_method = 'S256'),
    requested_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > requested_at AND expires_at <= requested_at + interval '10 minutes'),
    prompt TEXT NOT NULL,
    max_age_seconds BIGINT CHECK (max_age_seconds >= 0),
    browser_binding TEXT NOT NULL,
    login_session_id TEXT,
    login_cookie_digest TEXT,
    login_authenticated_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT auth_oidc_request_completion_check CHECK (
        (login_session_id IS NULL AND login_cookie_digest IS NULL AND login_authenticated_at IS NULL)
        OR (login_session_id IS NOT NULL AND login_cookie_digest IS NOT NULL AND login_authenticated_at IS NOT NULL
            AND octet_length(login_session_id) BETWEEN 1 AND 256
            AND octet_length(login_cookie_digest) BETWEEN 1 AND 256))
);
CREATE INDEX auth_oidc_requests_expiry_idx ON auth_oidc_authorization_requests (expires_at, selector);

CREATE TABLE auth_oidc_authorization_codes (
    selector TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    secret_digest BYTEA NOT NULL CHECK (octet_length(secret_digest) = 32),
    subject_id UUID NOT NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    security_version BIGINT NOT NULL CHECK (security_version > 0),
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    nonce TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL CHECK (code_challenge_method = 'S256'),
    authenticated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    session_id TEXT NOT NULL CHECK (octet_length(session_id) BETWEEN 1 AND 256),
    authorization_stamp TEXT NOT NULL CHECK (octet_length(authorization_stamp) BETWEEN 1 AND 192),
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    family_id UUID REFERENCES auth_oidc_refresh_families(id) ON DELETE CASCADE,
    CONSTRAINT auth_oidc_code_expiry_check CHECK (authenticated_at <= created_at AND expires_at > created_at
        AND expires_at <= created_at + interval '60 seconds' AND expires_at <= absolute_expires_at
        AND absolute_expires_at <= authenticated_at + interval '168 hours'),
    CONSTRAINT auth_oidc_code_family_check CHECK (family_id IS NULL OR consumed_at IS NOT NULL)
);
CREATE INDEX auth_oidc_codes_expiry_idx ON auth_oidc_authorization_codes (expires_at, selector);
CREATE INDEX auth_oidc_codes_family_idx ON auth_oidc_authorization_codes (family_id) WHERE family_id IS NOT NULL;

CREATE FUNCTION auth_oidc_family_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $guard$
BEGIN
    IF NOT ((NEW.session_id IS NULL AND NEW.authorization_stamp IS NULL AND NEW.absolute_expires_at IS NULL)
        OR (NEW.session_id IS NOT NULL AND NEW.authorization_stamp IS NOT NULL AND NEW.absolute_expires_at IS NOT NULL
            AND octet_length(NEW.session_id) BETWEEN 1 AND 256 AND octet_length(NEW.authorization_stamp) BETWEEN 1 AND 192
            AND NEW.expires_at = NEW.absolute_expires_at AND NEW.created_at < NEW.expires_at
            AND NEW.authenticated_at <= NEW.created_at AND NEW.absolute_expires_at <= NEW.authenticated_at + interval '168 hours')) THEN
        RAISE EXCEPTION 'invalid OIDC family profile' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN RETURN NEW; END IF;
    IF (OLD.session_id IS NULL) IS DISTINCT FROM (NEW.session_id IS NULL) THEN
        RAISE EXCEPTION 'OIDC refresh family profile is immutable' USING ERRCODE = '23514';
    END IF;
    IF OLD.session_id IS NOT NULL AND (
        (to_jsonb(NEW) - ARRAY['revoked_at','replayed_at']) IS DISTINCT FROM
        (to_jsonb(OLD) - ARRAY['revoked_at','replayed_at'])
        OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
        OR (OLD.replayed_at IS NOT NULL AND NEW.replayed_at IS DISTINCT FROM OLD.replayed_at)) THEN
        RAISE EXCEPTION 'OIDC refresh family binding and terminal state are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$guard$;
CREATE TRIGGER auth_oidc_family_guard BEFORE INSERT OR UPDATE ON auth_oidc_refresh_families
FOR EACH ROW EXECUTE FUNCTION auth_oidc_family_guard();

CREATE FUNCTION auth_oidc_token_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $guard$
DECLARE
    family_end timestamptz;
    prior_end timestamptz;
BEGIN
    SELECT absolute_expires_at INTO family_end FROM public.auth_oidc_refresh_families WHERE id = NEW.family_id;
    IF TG_OP = 'UPDATE' THEN
        SELECT absolute_expires_at INTO prior_end FROM public.auth_oidc_refresh_families WHERE id = OLD.family_id;
        IF (family_end IS NOT NULL OR prior_end IS NOT NULL) AND (
            (to_jsonb(NEW) - ARRAY['consumed_at','replaced_by_selector']) IS DISTINCT FROM
            (to_jsonb(OLD) - ARRAY['consumed_at','replaced_by_selector'])
            OR (OLD.consumed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD)
            OR (OLD.replaced_by_selector IS NOT NULL AND NEW.replaced_by_selector IS DISTINCT FROM OLD.replaced_by_selector)) THEN
            RAISE EXCEPTION 'OIDC token identity and consumption are immutable' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF family_end IS NOT NULL THEN
        IF NEW.expires_at > family_end OR NEW.expires_at <= NEW.created_at
            OR (NEW.replaced_by_selector IS NOT NULL AND (NEW.consumed_at IS NULL
                OR NEW.replaced_by_selector = NEW.selector
                OR NOT EXISTS (SELECT 1 FROM public.auth_oidc_refresh_tokens t
                    WHERE t.selector = NEW.replaced_by_selector AND t.family_id = NEW.family_id
                    AND t.consumed_at IS NULL))) THEN
            RAISE EXCEPTION 'OIDC token exceeds its family or has invalid successor' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$guard$;
CREATE TRIGGER auth_oidc_token_guard BEFORE INSERT OR UPDATE ON auth_oidc_refresh_tokens
FOR EACH ROW EXECUTE FUNCTION auth_oidc_token_guard();

CREATE FUNCTION auth_oidc_request_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $guard$
BEGIN
    IF NOT ((NEW.login_session_id IS NULL AND NEW.login_cookie_digest IS NULL AND NEW.login_authenticated_at IS NULL)
        OR (NEW.login_session_id IS NOT NULL AND NEW.login_cookie_digest IS NOT NULL AND NEW.login_authenticated_at IS NOT NULL
            AND octet_length(NEW.login_session_id) BETWEEN 1 AND 256 AND octet_length(NEW.login_cookie_digest) BETWEEN 1 AND 256))
        OR NEW.client_revision < 1 OR NEW.code_challenge_method <> 'S256' OR NEW.max_age_seconds < 0
        OR NEW.expires_at <= NEW.requested_at OR NEW.expires_at > NEW.requested_at + interval '10 minutes' THEN
        RAISE EXCEPTION 'invalid OIDC request' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN RETURN NEW; END IF;
    IF (to_jsonb(NEW) - ARRAY['login_session_id','login_cookie_digest','login_authenticated_at','consumed_at']) IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['login_session_id','login_cookie_digest','login_authenticated_at','consumed_at'])
       OR (OLD.login_session_id IS NOT NULL AND ROW(NEW.login_session_id,NEW.login_cookie_digest,NEW.login_authenticated_at)
           IS DISTINCT FROM ROW(OLD.login_session_id,OLD.login_cookie_digest,OLD.login_authenticated_at))
       OR (OLD.consumed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD) THEN
        RAISE EXCEPTION 'OIDC request and completion are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$guard$;
CREATE TRIGGER auth_oidc_request_guard BEFORE INSERT OR UPDATE ON auth_oidc_authorization_requests
FOR EACH ROW EXECUTE FUNCTION auth_oidc_request_guard();

CREATE FUNCTION auth_oidc_code_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $guard$
BEGIN
    IF NEW.security_version < 1 OR NEW.code_challenge_method <> 'S256'
        OR octet_length(NEW.session_id) NOT BETWEEN 1 AND 256 OR octet_length(NEW.authorization_stamp) NOT BETWEEN 1 AND 192
        OR NEW.authenticated_at > NEW.created_at OR NEW.expires_at <= NEW.created_at
        OR NEW.expires_at > NEW.created_at + interval '60 seconds' OR NEW.expires_at > NEW.absolute_expires_at
        OR NEW.absolute_expires_at > NEW.authenticated_at + interval '168 hours'
        OR (NEW.family_id IS NOT NULL AND NEW.consumed_at IS NULL) THEN
        RAISE EXCEPTION 'invalid OIDC code' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF (to_jsonb(NEW) - ARRAY['consumed_at','family_id']) IS DISTINCT FROM
           (to_jsonb(OLD) - ARRAY['consumed_at','family_id'])
           OR (OLD.consumed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD) THEN
            RAISE EXCEPTION 'OIDC code and consumption are immutable' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NEW.family_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM public.auth_oidc_refresh_families f WHERE f.id = NEW.family_id
          AND f.subject_id = NEW.subject_id AND f.client_id = NEW.client_id
          AND f.security_version = NEW.security_version AND f.authenticated_at = NEW.authenticated_at
          AND f.session_id = NEW.session_id AND f.authorization_stamp = NEW.authorization_stamp
          AND f.absolute_expires_at = NEW.absolute_expires_at AND f.scopes = NEW.scopes) THEN
        RAISE EXCEPTION 'OIDC code family binding mismatch' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$guard$;
CREATE TRIGGER auth_oidc_code_guard BEFORE INSERT OR UPDATE ON auth_oidc_authorization_codes
FOR EACH ROW EXECUTE FUNCTION auth_oidc_code_guard();

CREATE INDEX auth_oidc_tokens_successor_idx ON auth_oidc_refresh_tokens (replaced_by_selector) WHERE replaced_by_selector IS NOT NULL;
CREATE INDEX auth_oidc_families_expiry_idx ON auth_oidc_refresh_families (expires_at, id);
