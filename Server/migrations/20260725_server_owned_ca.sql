BEGIN;

-- A receipt contains no passport or biometric data. It records only that the
-- auth service independently verified one CA secure-messaging transcript,
-- bound to one App Attest key, one document challenge and one DG14 digest.
CREATE TABLE IF NOT EXISTS public.document_ca_receipts (
    session_id               uuid        PRIMARY KEY,
    contributor_id           uuid        NOT NULL
        REFERENCES public.contributors(id) ON DELETE CASCADE,
    attest_key_id            text        NOT NULL,
    document_challenge_id    text        NOT NULL,
    dg14_sha256              char(64)    NOT NULL,
    protocol_oid             text        NOT NULL,
    key_id                   bigint,
    verified_at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at               timestamptz NOT NULL,
    consumed_at              timestamptz,
    CONSTRAINT document_ca_receipts_attest_key_check
        CHECK (attest_key_id ~ '^[A-Za-z0-9+/]{43}=$'),
    CONSTRAINT document_ca_receipts_challenge_check
        CHECK (document_challenge_id ~ '^[A-Za-z0-9_-]{22}$'),
    CONSTRAINT document_ca_receipts_dg14_check
        CHECK (dg14_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT document_ca_receipts_protocol_check
        CHECK (protocol_oid IN (
            '0.4.0.127.0.7.2.2.3.2.2',
            '0.4.0.127.0.7.2.2.3.2.3',
            '0.4.0.127.0.7.2.2.3.2.4'
        )),
    CONSTRAINT document_ca_receipts_key_id_check
        CHECK (key_id IS NULL OR key_id BETWEEN 0 AND 4294967294),
    CONSTRAINT document_ca_receipts_lifetime_check
        CHECK (expires_at > verified_at AND expires_at <= verified_at + interval '5 minutes'),
    CONSTRAINT document_ca_receipts_consumed_check
        CHECK (consumed_at IS NULL OR consumed_at >= verified_at),
    CONSTRAINT document_ca_receipts_one_challenge
        UNIQUE (contributor_id, document_challenge_id)
);

CREATE INDEX IF NOT EXISTS idx_document_ca_receipts_expiry
    ON public.document_ca_receipts(expires_at)
    WHERE consumed_at IS NULL;

REVOKE ALL ON public.document_ca_receipts FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.document_ca_record_receipt(
    p_session_id uuid,
    p_contributor_id uuid,
    p_attest_key_id text,
    p_document_challenge_id text,
    p_dg14_sha256 text,
    p_protocol_oid text,
    p_key_id bigint,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_session_id IS NULL OR p_contributor_id IS NULL
       OR p_attest_key_id !~ '^[A-Za-z0-9+/]{43}=$'
       OR p_document_challenge_id !~ '^[A-Za-z0-9_-]{22}$'
       OR p_dg14_sha256 !~ '^[0-9a-f]{64}$'
       OR p_protocol_oid NOT IN (
           '0.4.0.127.0.7.2.2.3.2.2',
           '0.4.0.127.0.7.2.2.3.2.3',
           '0.4.0.127.0.7.2.2.3.2.4'
       )
       OR (p_key_id IS NOT NULL AND p_key_id NOT BETWEEN 0 AND 4294967294)
       OR p_expires_at <= clock_timestamp()
       OR p_expires_at > clock_timestamp() + interval '5 minutes' THEN
        RAISE EXCEPTION 'invalid document CA receipt';
    END IF;

    INSERT INTO public.document_ca_receipts(
        session_id, contributor_id, attest_key_id,
        document_challenge_id, dg14_sha256, protocol_oid, key_id, expires_at
    ) VALUES (
        p_session_id, p_contributor_id, p_attest_key_id,
        p_document_challenge_id, p_dg14_sha256, p_protocol_oid, p_key_id,
        p_expires_at
    );
    RETURN true;
EXCEPTION WHEN unique_violation THEN
    RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION public.document_ca_receipt_available(
    p_contributor_id uuid,
    p_attest_key_id text,
    p_document_challenge_id text,
    p_dg14_sha256 text
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT EXISTS(
        SELECT 1
          FROM public.document_ca_receipts
         WHERE contributor_id = p_contributor_id
           AND attest_key_id = p_attest_key_id
           AND document_challenge_id = p_document_challenge_id
           AND dg14_sha256 = p_dg14_sha256
           AND consumed_at IS NULL
           AND expires_at > clock_timestamp()
    );
$$;

REVOKE ALL ON FUNCTION public.document_ca_record_receipt(
    uuid, uuid, text, text, text, text, bigint, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.document_ca_receipt_available(
    uuid, text, text, text
) FROM PUBLIC;

-- v7 gains one authoritative CA assurance value. The old
-- chip_authentication_attested value remains review-only and is never enough
-- for automatic activation.
ALTER TABLE public.verification_requests
    DROP CONSTRAINT IF EXISTS verification_requests_document_assurance_check;
ALTER TABLE public.verification_requests
    ADD CONSTRAINT verification_requests_document_assurance_check
    CHECK (
        document_assurance IS NULL OR
        document_assurance IN (
            'passive_only',
            'chip_authentication_attested',
            'active_authentication',
            'chip_authentication_server'
        )
    );

ALTER TABLE public.verification_receipts
    DROP CONSTRAINT IF EXISTS verification_receipts_document_assurance_check;
ALTER TABLE public.verification_receipts
    ADD CONSTRAINT verification_receipts_document_assurance_check
    CHECK (
        (evidence_protocol = 6 AND document_assurance IS NULL) OR
        (evidence_protocol = 7 AND document_assurance IN (
            'active_authentication',
            'chip_authentication_server'
        ))
    );

CREATE OR REPLACE FUNCTION public.activate_self_hosted_verified_id_v7_rotating(
    p_document_token         text,
    p_legacy_document_token  text,
    p_contributor_id         uuid,
    p_request_id             uuid,
    p_policy_version         text,
    p_model_set_hash         text,
    p_receipt_digest         text,
    p_receipt_signature      text,
    p_service_timestamp      bigint,
    p_evidence_protocol      integer,
    p_document_assurance     text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_result text;
    v_updated integer;
BEGIN
    IF p_evidence_protocol IS DISTINCT FROM 7 OR
       p_document_assurance NOT IN (
           'active_authentication',
           'chip_authentication_server'
       ) THEN
        RETURN 'invalid';
    END IF;

    SELECT public.activate_self_hosted_verified_id_rotating(
        p_document_token,
        p_legacy_document_token,
        p_contributor_id,
        p_request_id,
        p_policy_version,
        p_model_set_hash,
        p_receipt_digest,
        p_receipt_signature,
        p_service_timestamp,
        6
    ) INTO v_result;

    IF v_result = 'verified' THEN
        UPDATE public.verification_receipts
           SET evidence_protocol = 7,
               document_assurance = p_document_assurance
         WHERE request_id = p_request_id
           AND contributor_id = p_contributor_id;
        GET DIAGNOSTICS v_updated = ROW_COUNT;
        IF v_updated <> 1 THEN
            RAISE EXCEPTION 'v7 receipt assurance update invariant failed';
        END IF;

        UPDATE public.contributors
           SET verification_method = CASE p_document_assurance
                   WHEN 'active_authentication'
                       THEN 'nfc_passport+pa+aa+self_hosted_v1'
                   ELSE 'nfc_passport+pa+server_ca+self_hosted_v1'
               END,
               identity_assurance = 'strong'
         WHERE id = p_contributor_id
           AND verified = true;
        GET DIAGNOSTICS v_updated = ROW_COUNT;
        IF v_updated <> 1 THEN
            RAISE EXCEPTION 'v7 contributor assurance update invariant failed';
        END IF;
    END IF;

    RETURN v_result;
END;
$$;

REVOKE ALL ON FUNCTION public.activate_self_hosted_verified_id_v7_rotating(
    text, text, uuid, uuid, text, text, text, text, bigint, integer, text
) FROM PUBLIC;

-- CA activation and receipt consumption are one database transaction. If the
-- receipt does not match or was replayed, the preceding Verified ID mutation
-- is rolled back by the exception.
CREATE OR REPLACE FUNCTION public.activate_self_hosted_verified_id_v7_ca_rotating(
    p_document_token         text,
    p_legacy_document_token  text,
    p_contributor_id         uuid,
    p_request_id             uuid,
    p_policy_version         text,
    p_model_set_hash         text,
    p_receipt_digest         text,
    p_receipt_signature      text,
    p_service_timestamp      bigint,
    p_evidence_protocol      integer,
    p_document_assurance     text,
    p_attest_key_id          text,
    p_document_challenge_id  text,
    p_dg14_sha256            text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_result text;
    v_updated integer;
BEGIN
    IF p_document_assurance IS DISTINCT FROM 'chip_authentication_server'
       OR p_attest_key_id !~ '^[A-Za-z0-9+/]{43}=$'
       OR p_document_challenge_id !~ '^[A-Za-z0-9_-]{22}$'
       OR p_dg14_sha256 !~ '^[0-9a-f]{64}$' THEN
        RETURN 'invalid';
    END IF;

    SELECT public.activate_self_hosted_verified_id_v7_rotating(
        p_document_token,
        p_legacy_document_token,
        p_contributor_id,
        p_request_id,
        p_policy_version,
        p_model_set_hash,
        p_receipt_digest,
        p_receipt_signature,
        p_service_timestamp,
        p_evidence_protocol,
        p_document_assurance
    ) INTO v_result;

    IF v_result = 'verified' THEN
        UPDATE public.document_ca_receipts
           SET consumed_at = clock_timestamp()
         WHERE contributor_id = p_contributor_id
           AND attest_key_id = p_attest_key_id
           AND document_challenge_id = p_document_challenge_id
           AND dg14_sha256 = p_dg14_sha256
           AND consumed_at IS NULL
           AND expires_at > clock_timestamp();
        GET DIAGNOSTICS v_updated = ROW_COUNT;
        IF v_updated <> 1 THEN
            RAISE EXCEPTION 'server-owned CA receipt missing or replayed';
        END IF;
    END IF;

    RETURN v_result;
END;
$$;

REVOKE ALL ON FUNCTION public.activate_self_hosted_verified_id_v7_ca_rotating(
    text, text, uuid, uuid, text, text, text, text, bigint, integer, text,
    text, text, text
) FROM PUBLIC;

COMMIT;
