-- Additive exact-request MFA interaction. Restart all writers after migration.
ALTER TABLE auth_oidc_authorization_requests
 ADD COLUMN interaction TEXT NOT NULL DEFAULT '',
 ADD COLUMN step_up_session JSONB,
 ADD COLUMN step_up_binding JSONB,
 ADD COLUMN step_up_session_id TEXT,
 ADD COLUMN step_up_cookie_digest TEXT,
 ADD COLUMN step_up_verified_at TIMESTAMPTZ,
 ADD CONSTRAINT auth_oidc_request_step_up_check CHECK ((
 (interaction IN ('','login') AND step_up_session IS NULL AND step_up_binding IS NULL
 AND step_up_session_id IS NULL AND step_up_cookie_digest IS NULL AND step_up_verified_at IS NULL)
 OR (interaction='step_up' AND step_up_session IS NOT NULL AND step_up_binding IS NOT NULL
 AND jsonb_typeof(step_up_session)='object' AND jsonb_typeof(step_up_binding)='object'
 AND octet_length(step_up_session->>'CookieDigest') BETWEEN 1 AND 256
 AND octet_length(step_up_session->>'SessionID') BETWEEN 1 AND 256
 AND step_up_session->>'SessionID'=step_up_binding->>'SessionID'
 AND step_up_binding->>'ClientID'=client_id
 AND login_session_id IS NULL AND login_cookie_digest IS NULL AND login_authenticated_at IS NULL
 AND expires_at <= requested_at + interval '3 minutes'
 AND ((step_up_session_id IS NULL AND step_up_cookie_digest IS NULL AND step_up_verified_at IS NULL)
 OR (step_up_session_id IS NOT NULL AND step_up_cookie_digest IS NOT NULL AND step_up_verified_at IS NOT NULL
 AND step_up_session_id=step_up_session->>'SessionID'
 AND octet_length(step_up_cookie_digest) BETWEEN 1 AND 256
 AND step_up_cookie_digest<>step_up_session->>'CookieDigest'
 AND step_up_verified_at>requested_at AND step_up_verified_at<expires_at)))) IS TRUE);

CREATE OR REPLACE FUNCTION auth_oidc_request_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $guard$
BEGIN
    IF NOT ((NEW.login_session_id IS NULL AND NEW.login_cookie_digest IS NULL AND NEW.login_authenticated_at IS NULL)
        OR (NEW.login_session_id IS NOT NULL AND NEW.login_cookie_digest IS NOT NULL AND NEW.login_authenticated_at IS NOT NULL
            AND octet_length(NEW.login_session_id) BETWEEN 1 AND 256 AND octet_length(NEW.login_cookie_digest) BETWEEN 1 AND 256))
        OR NEW.client_revision < 1 OR NEW.code_challenge_method <> 'S256' OR NEW.max_age_seconds < 0
        OR NEW.expires_at <= NEW.requested_at OR NEW.expires_at > NEW.requested_at + interval '10 minutes' THEN
        RAISE EXCEPTION 'invalid OIDC request' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.login_session_id IS NOT NULL OR NEW.step_up_session_id IS NOT NULL OR NEW.consumed_at IS NOT NULL THEN
            RAISE EXCEPTION 'OIDC request must start pending' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF (to_jsonb(NEW) - ARRAY['login_session_id','login_cookie_digest','login_authenticated_at','step_up_session_id','step_up_cookie_digest','step_up_verified_at','consumed_at']) IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['login_session_id','login_cookie_digest','login_authenticated_at','step_up_session_id','step_up_cookie_digest','step_up_verified_at','consumed_at'])
       OR (OLD.login_session_id IS NOT NULL AND ROW(NEW.login_session_id,NEW.login_cookie_digest,NEW.login_authenticated_at)
           IS DISTINCT FROM ROW(OLD.login_session_id,OLD.login_cookie_digest,OLD.login_authenticated_at))
       OR (OLD.step_up_session_id IS NOT NULL AND ROW(NEW.step_up_session_id,NEW.step_up_cookie_digest,NEW.step_up_verified_at)
           IS DISTINCT FROM ROW(OLD.step_up_session_id,OLD.step_up_cookie_digest,OLD.step_up_verified_at))
       OR (OLD.consumed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD)
       OR (NEW.consumed_at IS NOT NULL AND OLD.login_session_id IS NULL AND OLD.step_up_session_id IS NULL)
       OR (NEW.login_authenticated_at IS NOT NULL AND (NEW.login_authenticated_at<NEW.requested_at OR NEW.login_authenticated_at>=NEW.expires_at)) THEN
        RAISE EXCEPTION 'OIDC request and completion are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$guard$;
