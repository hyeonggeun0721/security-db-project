--
-- PostgreSQL database dump
--

\restrict B8VbOjfHSaVolqqL2rtkPDG9Tug4odG0yKAaw0QGaaKiVdj00owxVI65wduXuxH

-- Dumped from database version 15.19 (Homebrew)
-- Dumped by pg_dump version 15.19 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: vector; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;


--
-- Name: EXTENSION vector; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION vector IS 'vector data type and ivfflat and hnsw access methods';


--
-- Name: fn_archive_audit_log(interval); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_archive_audit_log(p_retention interval DEFAULT '1 year'::interval) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
    v_cutoff timestamptz := now() - p_retention;
    v_moved  bigint;
BEGIN
    -- 변경 차단 트리거를 이 트랜잭션에 한해 예외 처리
    PERFORM set_config('audit_log.maintenance', 'on', true);  -- true = SET LOCAL

    WITH cte AS (
        DELETE FROM audit_log
        WHERE changed_at < v_cutoff
        RETURNING audit_id, table_name, row_pk, operation, old_data, new_data, changed_by, changed_at
    )
    INSERT INTO audit_log_archive
        (audit_id, table_name, row_pk, operation, old_data, new_data, changed_by, changed_at)
    SELECT audit_id, table_name, row_pk, operation, old_data, new_data, changed_by, changed_at
    FROM cte;

    GET DIAGNOSTICS v_moved = ROW_COUNT;
    RETURN v_moved;
END;
$$;


--
-- Name: FUNCTION fn_archive_audit_log(p_retention interval); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.fn_archive_audit_log(p_retention interval) IS 'audit_log 보존기간 경과분 이관. SECURITY DEFINER + search_path 고정으로 하이재킹 차단.';


--
-- Name: fn_asset_department(integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_asset_department(p_asset_id integer) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
    SELECT a.department FROM assets a WHERE a.asset_id = p_asset_id;
$$;


--
-- Name: FUNCTION fn_asset_department(p_asset_id integer); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.fn_asset_department(p_asset_id integer) IS 'asset_id -> 부서 (RLS 우회 조회용). SECURITY DEFINER + search_path 고정으로 하이재킹 차단.';


--
-- Name: fn_audit_log_block_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_audit_log_block_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- 보존정책 함수가 SET LOCAL 로 켠 경우에만 통과
    IF current_setting('audit_log.maintenance', true) = 'on' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NULL; -- TRUNCATE(문 단위)
    END IF;

    RAISE EXCEPTION 'audit_log 는 append-only 입니다: % 불가 (보존정책 함수만 예외)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;


--
-- Name: fn_audit_row_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_audit_row_change() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
    v_row_pk     TEXT;
    v_old        JSONB := NULL;
    v_new        JSONB := NULL;
    v_changed_at TIMESTAMPTZ := now();   -- 원본 DEFAULT now() 의미 유지
    v_actor      TEXT := session_user;
    v_prev       TEXT;
    v_hash       TEXT;
BEGIN
    IF (TG_OP = 'DELETE') THEN
        v_old := to_jsonb(OLD);
    ELSIF (TG_OP = 'INSERT') THEN
        v_new := to_jsonb(NEW);
    ELSE  -- UPDATE
        v_old := to_jsonb(OLD);
        v_new := to_jsonb(NEW);
    END IF;

    v_row_pk := CASE TG_TABLE_NAME
        WHEN 'security_events' THEN COALESCE(v_new ->> 'event_id',    v_old ->> 'event_id')
        WHEN 'responses'       THEN COALESCE(v_new ->> 'response_id', v_old ->> 'response_id')
        ELSE NULL
    END;

    -- 직전 행의 row_hash (없으면 genesis)
    SELECT row_hash INTO v_prev FROM audit_log ORDER BY audit_id DESC LIMIT 1;
    v_prev := COALESCE(v_prev, repeat('0', 64));

    v_hash := encode(sha256(convert_to(
          v_prev
       || '|' || TG_TABLE_NAME
       || '|' || COALESCE(v_row_pk, '')
       || '|' || TG_OP
       || '|' || COALESCE(v_old::text, '')
       || '|' || COALESCE(v_new::text, '')
       || '|' || v_actor
       || '|' || v_changed_at::text
       , 'UTF8')), 'hex');

    INSERT INTO audit_log (table_name, row_pk, operation, old_data, new_data,
                           changed_by, changed_at, prev_hash, row_hash)
    VALUES (TG_TABLE_NAME, v_row_pk, TG_OP, v_old, v_new,
            v_actor, v_changed_at, v_prev, v_hash);

    IF (TG_OP = 'DELETE') THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: FUNCTION fn_audit_row_change(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.fn_audit_row_change() IS 'security_events/responses 공용 감사 트리거. SECURITY DEFINER + search_path 고정. 각 행에 해시 체인(prev_hash/row_hash) 기록.';


--
-- Name: fn_current_dept(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_current_dept() RETURNS text
    LANGUAGE sql STABLE
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
    SELECT COALESCE(
        NULLIF(current_setting('app.department', true), ''),
        (SELECT r.department FROM rls_role_department r WHERE r.role_name = current_user)
    );
$$;


--
-- Name: FUNCTION fn_current_dept(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.fn_current_dept() IS '현재 세션의 부서 컨텍스트(RLS). SECURITY INVOKER 지만 RLS 경로라 search_path 고정으로 하이재킹 차단.';


--
-- Name: fn_cvss_band(numeric); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_cvss_band(p_score numeric) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT CASE
        WHEN p_score IS NULL      THEN NULL
        WHEN p_score >= 9.0       THEN 'CRITICAL'
        WHEN p_score >= 7.0       THEN 'HIGH'
        WHEN p_score >= 4.0       THEN 'MEDIUM'
        WHEN p_score >  0.0       THEN 'LOW'
        ELSE 'NONE'
    END;
$$;


--
-- Name: FUNCTION fn_cvss_band(p_score numeric); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.fn_cvss_band(p_score numeric) IS 'CVSS v3.x 점수를 정성 등급(NONE/LOW/MEDIUM/HIGH/CRITICAL)으로 변환';


--
-- Name: fn_event_department(integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_event_department(p_event_id integer) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
    SELECT a.department
    FROM security_events e
    JOIN assets a ON a.asset_id = e.asset_id
    WHERE e.event_id = p_event_id;
$$;


--
-- Name: FUNCTION fn_event_department(p_event_id integer); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.fn_event_department(p_event_id integer) IS 'event_id -> 자산 부서 (RLS 우회 조회용). SECURITY DEFINER + search_path 고정으로 하이재킹 차단.';


--
-- Name: fn_refresh_risk_score(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_refresh_risk_score() RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_asset_risk_score;
END;
$$;


--
-- Name: FUNCTION fn_refresh_risk_score(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.fn_refresh_risk_score() IS 'mv_asset_risk_score 를 CONCURRENTLY 갱신. 운영에서는 pg_cron 등으로 주기 실행.';


--
-- Name: fn_severity_rank(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_severity_rank(p_label text) RETURNS integer
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT CASE upper(p_label)
        WHEN 'NONE'     THEN 0
        WHEN 'LOW'      THEN 1
        WHEN 'MEDIUM'   THEN 2
        WHEN 'HIGH'     THEN 3
        WHEN 'CRITICAL' THEN 4
        ELSE NULL
    END;
$$;


--
-- Name: fn_validate_response_timing(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_validate_response_timing() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
    v_detected_at TIMESTAMPTZ;
BEGIN
    SELECT detected_at INTO v_detected_at
    FROM security_events
    WHERE event_id = NEW.event_id;

    IF v_detected_at IS NULL THEN
        -- event_id FK 가 보장하므로 정상적으로는 도달 불가
        RAISE EXCEPTION 'responses.event_id=% 에 해당하는 security_events 가 없습니다', NEW.event_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF NEW.action_date < v_detected_at THEN
        RAISE EXCEPTION
          '대응 시각(action_date=%)이 사건 탐지 시각(detected_at=%)보다 앞설 수 없습니다 (event_id=%)',
          NEW.action_date, v_detected_at, NEW.event_id
          USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: FUNCTION fn_validate_response_timing(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.fn_validate_response_timing() IS 'responses BEFORE INSERT/UPDATE: action_date 가 연결 이벤트 detected_at 보다 이르면 거부. SECURITY DEFINER + search_path 고정.';


--
-- Name: fn_verify_audit_chain(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_verify_audit_chain() RETURNS TABLE(audit_id bigint, problem text, expected_hash text, stored_hash text)
    LANGUAGE plpgsql STABLE
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
    r      RECORD;
    v_prev TEXT := repeat('0', 64);   -- genesis
    v_calc TEXT;
BEGIN
    FOR r IN SELECT * FROM audit_log ORDER BY audit_id LOOP
        v_calc := encode(sha256(convert_to(
              v_prev
           || '|' || r.table_name
           || '|' || COALESCE(r.row_pk, '')
           || '|' || r.operation
           || '|' || COALESCE(r.old_data::text, '')
           || '|' || COALESCE(r.new_data::text, '')
           || '|' || r.changed_by
           || '|' || r.changed_at::text
           , 'UTF8')), 'hex');

        IF r.prev_hash IS DISTINCT FROM v_prev THEN
            audit_id := r.audit_id;
            problem  := 'prev_hash 링크 끊김 (직전 행이 삭제/삽입/재정렬됨)';
            expected_hash := v_prev; stored_hash := r.prev_hash;
            RETURN NEXT;
        END IF;

        IF r.row_hash IS DISTINCT FROM v_calc THEN
            audit_id := r.audit_id;
            problem  := 'row_hash 불일치 (이 행 내용이 조작됨)';
            expected_hash := v_calc; stored_hash := r.row_hash;
            RETURN NEXT;
        END IF;

        -- 다음 반복의 prev 비교 기준은 "저장된" row_hash (조작 지점을 정확히 1행으로 국한)
        v_prev := r.row_hash;
    END LOOP;
END $$;


--
-- Name: FUNCTION fn_verify_audit_chain(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.fn_verify_audit_chain() IS 'audit_log 해시 체인 무결성 검증. 조작/삭제/삽입된 지점을 행으로 반환. 0행이면 무결.';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alert_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_log (
    alert_id bigint NOT NULL,
    alert_type text NOT NULL,
    ref_key text NOT NULL,
    severity text,
    summary text NOT NULL,
    channels text[] DEFAULT '{}'::text[] NOT NULL,
    is_synthetic boolean DEFAULT false NOT NULL,
    payload jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT alert_log_alert_type_check CHECK ((alert_type = ANY (ARRAY['CRITICAL_EVENT'::text, 'AUDIT_CHAIN'::text])))
);


--
-- Name: TABLE alert_log; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.alert_log IS '알림 발송 이력 + 중복 방지. (alert_type, ref_key) 가 이미 있으면 재발송 안 함.';


--
-- Name: COLUMN alert_log.ref_key; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.alert_log.ref_key IS 'CRITICAL_EVENT=security_events.event_id, AUDIT_CHAIN=db명:breaks:깨진audit_id들 지문';


--
-- Name: alert_log_alert_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.alert_log_alert_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alert_log_alert_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.alert_log_alert_id_seq OWNED BY public.alert_log.alert_id;


--
-- Name: asset_vulnerabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.asset_vulnerabilities (
    asset_id integer NOT NULL,
    vuln_id integer NOT NULL,
    detected_date date DEFAULT CURRENT_DATE NOT NULL,
    status character varying(15) DEFAULT 'OPEN'::character varying NOT NULL,
    scan_run_id integer,
    observed_detail text,
    CONSTRAINT asset_vulnerabilities_status_check CHECK (((status)::text = ANY ((ARRAY['OPEN'::character varying, 'PATCHED'::character varying, 'ACCEPTED_RISK'::character varying])::text[])))
);


--
-- Name: COLUMN asset_vulnerabilities.scan_run_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.asset_vulnerabilities.scan_run_id IS '이 연결을 만든 스캔 실행 (SCAN 출처일 때). 수동 연결은 NULL.';


--
-- Name: COLUMN asset_vulnerabilities.observed_detail; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.asset_vulnerabilities.observed_detail IS '해당 호스트에서 관측된 실제 설정값 (KISA current_setting).';


--
-- Name: assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assets (
    asset_id integer NOT NULL,
    asset_name character varying(100) NOT NULL,
    asset_type character varying(30) NOT NULL,
    ip_address inet,
    department character varying(50),
    importance_level smallint DEFAULT 3 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT assets_asset_type_check CHECK (((asset_type)::text = ANY ((ARRAY['SERVER'::character varying, 'NETWORK'::character varying, 'APPLICATION'::character varying, 'DATABASE'::character varying, 'ENDPOINT'::character varying])::text[]))),
    CONSTRAINT assets_importance_level_check CHECK (((importance_level >= 1) AND (importance_level <= 5)))
);


--
-- Name: assets_asset_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.assets_asset_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: assets_asset_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.assets_asset_id_seq OWNED BY public.assets.asset_id;


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    audit_id bigint NOT NULL,
    table_name text NOT NULL,
    row_pk text,
    operation text NOT NULL,
    old_data jsonb,
    new_data jsonb,
    changed_by text DEFAULT CURRENT_USER NOT NULL,
    changed_at timestamp with time zone DEFAULT now() NOT NULL,
    prev_hash text,
    row_hash text,
    CONSTRAINT audit_log_operation_check CHECK ((operation = ANY (ARRAY['INSERT'::text, 'UPDATE'::text, 'DELETE'::text])))
);


--
-- Name: TABLE audit_log; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.audit_log IS 'security_events / responses 변경 감사 로그 (트리거 자동 기록)';


--
-- Name: COLUMN audit_log.old_data; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.audit_log.old_data IS '변경 전 행 스냅샷(JSONB). INSERT의 경우 NULL';


--
-- Name: COLUMN audit_log.new_data; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.audit_log.new_data IS '변경 후 행 스냅샷(JSONB). DELETE의 경우 NULL';


--
-- Name: COLUMN audit_log.prev_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.audit_log.prev_hash IS '직전 행(audit_id 최대)의 row_hash. 첫 행은 genesis(64자 0).';


--
-- Name: COLUMN audit_log.row_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.audit_log.row_hash IS 'sha256(prev_hash || 이번 행 내용). 해시 체인 위변조 탐지용.';


--
-- Name: audit_log_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_log_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_log_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_log_audit_id_seq OWNED BY public.audit_log.audit_id;


--
-- Name: audit_log_archive; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log_archive (
    audit_id bigint DEFAULT nextval('public.audit_log_audit_id_seq'::regclass) NOT NULL,
    table_name text NOT NULL,
    row_pk text,
    operation text NOT NULL,
    old_data jsonb,
    new_data jsonb,
    changed_by text DEFAULT CURRENT_USER NOT NULL,
    changed_at timestamp with time zone DEFAULT now() NOT NULL,
    archived_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE audit_log_archive; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.audit_log_archive IS 'audit_log 보존기간 경과분 이관 보관소 (fn_archive_audit_log 가 채움)';


--
-- Name: COLUMN audit_log_archive.old_data; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.audit_log_archive.old_data IS '변경 전 행 스냅샷(JSONB). INSERT의 경우 NULL';


--
-- Name: COLUMN audit_log_archive.new_data; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.audit_log_archive.new_data IS '변경 후 행 스냅샷(JSONB). DELETE의 경우 NULL';


--
-- Name: departments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.departments (
    dept_name character varying(50) NOT NULL,
    dept_description text
);


--
-- Name: TABLE departments; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.departments IS '부서 마스터. assets/staff/rls_role_department.department 가 참조';


--
-- Name: event_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_types (
    event_type_name character varying(30) NOT NULL,
    description text,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE event_types; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.event_types IS 'security_events.event_type 마스터. 새 유형은 INSERT 로 추가(권한: security_admin).';


--
-- Name: COLUMN event_types.is_active; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.event_types.is_active IS 'false = 신규 사용 비권장(과거 이벤트 참조는 유지). FK 는 이 값을 보지 않음.';


--
-- Name: vulnerabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerabilities (
    vuln_id integer NOT NULL,
    cve_id character varying(20),
    description text,
    cvss_score numeric(3,1),
    severity character varying(10) NOT NULL,
    published_date date,
    attack_tactic character varying(40),
    attack_tactic_id character varying(10),
    attack_technique character varying(10),
    attack_technique_name character varying(80),
    source character varying(10) DEFAULT 'NVD'::character varying NOT NULL,
    finding_ref character varying(40),
    remediation text,
    CONSTRAINT chk_vuln_scan_ident CHECK ((((source)::text <> 'SCAN'::text) OR ((cve_id IS NULL) AND (finding_ref IS NOT NULL)))),
    CONSTRAINT chk_vuln_source CHECK (((source)::text = ANY ((ARRAY['NVD'::character varying, 'SCAN'::character varying, 'MANUAL'::character varying])::text[]))),
    CONSTRAINT chk_vulnerabilities_cve_id_format CHECK (((cve_id IS NULL) OR ((cve_id)::text ~ '^CVE-\d{4}-\d{4,}$'::text))),
    CONSTRAINT vulnerabilities_cvss_score_check CHECK (((cvss_score >= (0)::numeric) AND (cvss_score <= (10)::numeric))),
    CONSTRAINT vulnerabilities_severity_check CHECK (((severity)::text = ANY ((ARRAY['LOW'::character varying, 'MEDIUM'::character varying, 'HIGH'::character varying, 'CRITICAL'::character varying])::text[])))
);


--
-- Name: COLUMN vulnerabilities.attack_tactic; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.vulnerabilities.attack_tactic IS 'MITRE ATT&CK Enterprise Tactic 명칭';


--
-- Name: COLUMN vulnerabilities.attack_tactic_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.vulnerabilities.attack_tactic_id IS 'ATT&CK Tactic ID (예: TA0004)';


--
-- Name: COLUMN vulnerabilities.attack_technique; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.vulnerabilities.attack_technique IS 'ATT&CK Technique ID (예: T1068)';


--
-- Name: COLUMN vulnerabilities.attack_technique_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.vulnerabilities.attack_technique_name IS 'ATT&CK Technique 명칭';


--
-- Name: COLUMN vulnerabilities.source; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.vulnerabilities.source IS 'NVD=CVE(외부), SCAN=설정취약점 진단(KISA 등), MANUAL=수동 등록';


--
-- Name: COLUMN vulnerabilities.finding_ref; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.vulnerabilities.finding_ref IS 'CVE 가 아닌 외부 식별자 (예: KISA-U-47). source=SCAN 이면 필수, UNIQUE.';


--
-- Name: COLUMN vulnerabilities.remediation; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.vulnerabilities.remediation IS '조치 권고 (SCAN/MANUAL 에서 사용). NVD 행은 보통 NULL.';


--
-- Name: mv_asset_risk_score; Type: MATERIALIZED VIEW; Schema: public; Owner: -
--

CREATE MATERIALIZED VIEW public.mv_asset_risk_score AS
 WITH open_vuln AS (
         SELECT av.asset_id,
            count(*) AS open_vuln_count,
            max(v.cvss_score) AS max_open_cvss,
            round(avg(v.cvss_score), 2) AS avg_open_cvss
           FROM (public.asset_vulnerabilities av
             JOIN public.vulnerabilities v ON ((v.vuln_id = av.vuln_id)))
          WHERE ((av.status)::text = 'OPEN'::text)
          GROUP BY av.asset_id
        )
 SELECT a.asset_id,
    a.asset_name,
    a.asset_type,
    a.department,
    a.importance_level,
    COALESCE(ov.open_vuln_count, (0)::bigint) AS open_vuln_count,
    (COALESCE(ov.max_open_cvss, (0)::numeric))::numeric(3,1) AS max_open_cvss,
    (COALESCE(ov.avg_open_cvss, (0)::numeric))::numeric(4,2) AS avg_open_cvss,
    round(((a.importance_level)::numeric * COALESCE(ov.max_open_cvss, (0)::numeric)), 1) AS risk_score,
        CASE
            WHEN (((a.importance_level)::numeric * COALESCE(ov.max_open_cvss, (0)::numeric)) >= (40)::numeric) THEN 'CRITICAL'::text
            WHEN (((a.importance_level)::numeric * COALESCE(ov.max_open_cvss, (0)::numeric)) >= (24)::numeric) THEN 'HIGH'::text
            WHEN (((a.importance_level)::numeric * COALESCE(ov.max_open_cvss, (0)::numeric)) >= (10)::numeric) THEN 'MEDIUM'::text
            ELSE 'LOW'::text
        END AS risk_label,
    now() AS refreshed_at
   FROM (public.assets a
     LEFT JOIN open_vuln ov ON ((ov.asset_id = a.asset_id)))
  WITH NO DATA;


--
-- Name: MATERIALIZED VIEW mv_asset_risk_score; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON MATERIALIZED VIEW public.mv_asset_risk_score IS 'vw_asset_risk_score 의 구체화 버전(스냅샷). fn_refresh_risk_score() 로 갱신. refreshed_at 에 마지막 갱신시각.';


--
-- Name: nvd_cve_details; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nvd_cve_details (
    cve_id character varying(20) NOT NULL,
    nvd_cvss_score numeric(3,1),
    nvd_severity character varying(20),
    nvd_cvss_version character varying(10),
    nvd_vector_string text,
    nvd_description text,
    nvd_published_date timestamp with time zone,
    nvd_last_modified timestamp with time zone,
    nvd_reference_urls text[],
    nvd_status character varying(20) DEFAULT 'SYNCED'::character varying NOT NULL,
    synced_at timestamp with time zone DEFAULT now() NOT NULL,
    epss_score numeric(8,7),
    epss_percentile numeric(8,7),
    epss_model_date date,
    epss_updated_at timestamp with time zone,
    CONSTRAINT chk_epss_percentile CHECK (((epss_percentile IS NULL) OR ((epss_percentile >= (0)::numeric) AND (epss_percentile <= (1)::numeric)))),
    CONSTRAINT chk_epss_score CHECK (((epss_score IS NULL) OR ((epss_score >= (0)::numeric) AND (epss_score <= (1)::numeric)))),
    CONSTRAINT chk_nvd_cve_details_nvd_severity CHECK (((nvd_severity IS NULL) OR ((nvd_severity)::text = ANY ((ARRAY['NONE'::character varying, 'LOW'::character varying, 'MEDIUM'::character varying, 'HIGH'::character varying, 'CRITICAL'::character varying])::text[])))),
    CONSTRAINT nvd_cve_details_nvd_status_check CHECK (((nvd_status)::text = ANY ((ARRAY['SYNCED'::character varying, 'NOT_FOUND'::character varying, 'ERROR'::character varying, 'PENDING'::character varying])::text[])))
);


--
-- Name: TABLE nvd_cve_details; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.nvd_cve_details IS 'vulnerabilities.cve_id 별 NVD REST API 2.0 공식 상세 (nvd_sync.py 가 UPSERT)';


--
-- Name: COLUMN nvd_cve_details.nvd_status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.nvd_cve_details.nvd_status IS 'SYNCED=조회성공, NOT_FOUND=NVD에 해당 CVE 없음, ERROR=조회실패';


--
-- Name: COLUMN nvd_cve_details.epss_score; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.nvd_cve_details.epss_score IS 'EPSS 악용확률 0~1 (FIRST.org). 향후 30일 내 악용 활동 관측 확률.';


--
-- Name: COLUMN nvd_cve_details.epss_percentile; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.nvd_cve_details.epss_percentile IS 'EPSS 백분위 0~1 (전체 CVE 대비 상대 순위).';


--
-- Name: COLUMN nvd_cve_details.epss_model_date; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.nvd_cve_details.epss_model_date IS 'EPSS API 응답의 date (모델 산출 기준일).';


--
-- Name: nvd_watch_candidates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nvd_watch_candidates (
    cve_id character varying(20) NOT NULL,
    matched_keywords text[] NOT NULL,
    nvd_cvss_score numeric(3,1),
    nvd_severity character varying(20),
    nvd_description text,
    nvd_published_date timestamp with time zone,
    nvd_reference_urls text[],
    already_in_vulnerabilities boolean DEFAULT false NOT NULL,
    review_status character varying(20) DEFAULT 'NEW'::character varying NOT NULL,
    discovered_at timestamp with time zone DEFAULT now() NOT NULL,
    synced_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_nvd_watch_candidates_nvd_severity CHECK (((nvd_severity IS NULL) OR ((nvd_severity)::text = ANY ((ARRAY['NONE'::character varying, 'LOW'::character varying, 'MEDIUM'::character varying, 'HIGH'::character varying, 'CRITICAL'::character varying])::text[])))),
    CONSTRAINT nvd_watch_candidates_review_status_check CHECK (((review_status)::text = ANY ((ARRAY['NEW'::character varying, 'REVIEWED'::character varying, 'IMPORTED'::character varying, 'IGNORED'::character varying])::text[])))
);


--
-- Name: TABLE nvd_watch_candidates; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.nvd_watch_candidates IS 'NVD 키워드 검색으로 발견한 최근 신규 CVE 후보. vulnerabilities 로 자동 병합하지 않음(검토 큐)';


--
-- Name: responses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.responses (
    response_id integer NOT NULL,
    event_id integer NOT NULL,
    staff_id integer NOT NULL,
    action_taken text NOT NULL,
    action_date timestamp with time zone DEFAULT now() NOT NULL,
    status character varying(15) DEFAULT 'IN_PROGRESS'::character varying NOT NULL,
    CONSTRAINT responses_status_check CHECK (((status)::text = ANY ((ARRAY['IN_PROGRESS'::character varying, 'COMPLETED'::character varying])::text[])))
);


--
-- Name: responses_response_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.responses_response_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: responses_response_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.responses_response_id_seq OWNED BY public.responses.response_id;


--
-- Name: rls_role_department; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rls_role_department (
    role_name text NOT NULL,
    department character varying(50) NOT NULL
);


--
-- Name: scan_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_runs (
    scan_run_id integer NOT NULL,
    tool character varying(50) DEFAULT 'KISA-U (U-01~U-72)'::character varying NOT NULL,
    target_asset_id integer,
    target_hostname character varying(100),
    target_platform character varying(60),
    target_distro character varying(80),
    scanned_as_root boolean,
    scanned_at timestamp with time zone DEFAULT now() NOT NULL,
    total_checks integer,
    cnt_good integer,
    cnt_vuln integer,
    cnt_na integer,
    report_path text,
    imported_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE scan_runs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.scan_runs IS '설정취약점 스캐너 1회 실행 메타 (KISA kisa_scanner.py 등). 개별 취약 항목은 vulnerabilities(source=SCAN) + asset_vulnerabilities 로 적재.';


--
-- Name: scan_runs_scan_run_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scan_runs_scan_run_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scan_runs_scan_run_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scan_runs_scan_run_id_seq OWNED BY public.scan_runs.scan_run_id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version text NOT NULL,
    filename text NOT NULL,
    checksum text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL,
    applied_by text DEFAULT SESSION_USER NOT NULL,
    exec_seconds numeric(10,3)
);


--
-- Name: TABLE schema_migrations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.schema_migrations IS 'migrate.py 마이그레이션 이력. version=Vnnn, checksum=파일 sha256. 적용된 행의 파일을 수정하면 drift 로 차단됨.';


--
-- Name: security_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.security_events (
    event_id integer NOT NULL,
    asset_id integer NOT NULL,
    vuln_id integer,
    event_type character varying(30) NOT NULL,
    severity character varying(10) NOT NULL,
    detected_at timestamp with time zone DEFAULT now() NOT NULL,
    status character varying(15) DEFAULT 'OPEN'::character varying NOT NULL,
    description text,
    CONSTRAINT security_events_severity_check CHECK (((severity)::text = ANY ((ARRAY['LOW'::character varying, 'MEDIUM'::character varying, 'HIGH'::character varying, 'CRITICAL'::character varying])::text[]))),
    CONSTRAINT security_events_status_check CHECK (((status)::text = ANY ((ARRAY['OPEN'::character varying, 'IN_PROGRESS'::character varying, 'RESOLVED'::character varying])::text[])))
);


--
-- Name: COLUMN security_events.description; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.security_events.description IS '이벤트 상세 메모(자유 텍스트). ''[SIM] '' 접두사 = 합성/시뮬레이션 데이터(실사건 아님).';


--
-- Name: security_events_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.security_events_event_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: security_events_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.security_events_event_id_seq OWNED BY public.security_events.event_id;


--
-- Name: staff; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.staff (
    staff_id integer NOT NULL,
    staff_name character varying(50) NOT NULL,
    department character varying(50),
    role character varying(30),
    CONSTRAINT staff_role_check CHECK (((role)::text = ANY ((ARRAY['ANALYST'::character varying, 'ADMIN'::character varying, 'MANAGER'::character varying])::text[])))
);


--
-- Name: staff_staff_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.staff_staff_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: staff_staff_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.staff_staff_id_seq OWNED BY public.staff.staff_id;


--
-- Name: threat_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_reports (
    report_id integer NOT NULL,
    title character varying(200) NOT NULL,
    content text NOT NULL,
    report_date date,
    related_event_id integer,
    embedding public.vector(384)
);


--
-- Name: threat_reports_report_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_reports_report_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_reports_report_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_reports_report_id_seq OWNED BY public.threat_reports.report_id;


--
-- Name: vulnerabilities_vuln_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vulnerabilities_vuln_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vulnerabilities_vuln_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vulnerabilities_vuln_id_seq OWNED BY public.vulnerabilities.vuln_id;


--
-- Name: vw_asset_risk_score; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_asset_risk_score AS
 WITH open_vuln AS (
         SELECT av.asset_id,
            count(*) AS open_vuln_count,
            max(v.cvss_score) AS max_open_cvss,
            round(avg(v.cvss_score), 2) AS avg_open_cvss
           FROM (public.asset_vulnerabilities av
             JOIN public.vulnerabilities v ON ((v.vuln_id = av.vuln_id)))
          WHERE ((av.status)::text = 'OPEN'::text)
          GROUP BY av.asset_id
        )
 SELECT a.asset_id,
    a.asset_name,
    a.asset_type,
    a.department,
    a.importance_level,
    COALESCE(ov.open_vuln_count, (0)::bigint) AS open_vuln_count,
    (COALESCE(ov.max_open_cvss, (0)::numeric))::numeric(3,1) AS max_open_cvss,
    (COALESCE(ov.avg_open_cvss, (0)::numeric))::numeric(4,2) AS avg_open_cvss,
    round(((a.importance_level)::numeric * COALESCE(ov.max_open_cvss, (0)::numeric)), 1) AS risk_score,
        CASE
            WHEN (((a.importance_level)::numeric * COALESCE(ov.max_open_cvss, (0)::numeric)) >= (40)::numeric) THEN 'CRITICAL'::text
            WHEN (((a.importance_level)::numeric * COALESCE(ov.max_open_cvss, (0)::numeric)) >= (24)::numeric) THEN 'HIGH'::text
            WHEN (((a.importance_level)::numeric * COALESCE(ov.max_open_cvss, (0)::numeric)) >= (10)::numeric) THEN 'MEDIUM'::text
            ELSE 'LOW'::text
        END AS risk_label
   FROM (public.assets a
     LEFT JOIN open_vuln ov ON ((ov.asset_id = a.asset_id)));


--
-- Name: VIEW vw_asset_risk_score; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.vw_asset_risk_score IS '자산 중요도(importance_level) x 미해결 취약점 최대 CVSS 로 계산한 위험도 점수/라벨';


--
-- Name: vw_asset_vuln_summary; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_asset_vuln_summary AS
 SELECT a.asset_id,
    a.asset_name,
    count(*) FILTER (WHERE ((av.status)::text = 'OPEN'::text)) AS open_vuln_count,
    count(*) AS total_vuln_count
   FROM (public.assets a
     JOIN public.asset_vulnerabilities av ON ((av.asset_id = a.asset_id)))
  GROUP BY a.asset_id, a.asset_name;


--
-- Name: vw_assets_dept; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_assets_dept WITH (security_invoker='true') AS
 SELECT assets.asset_id,
    assets.asset_name,
    assets.asset_type,
    assets.department,
    assets.importance_level,
    assets.created_at
   FROM public.assets;


--
-- Name: VIEW vw_assets_dept; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.vw_assets_dept IS '부서 계정용 assets 뷰 (ip_address 제외, security_invoker). 행 필터는 호출자 기준 assets RLS 를 상속.';


--
-- Name: vw_cvss_nvd_mismatch; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_cvss_nvd_mismatch AS
 SELECT v.vuln_id,
    v.cve_id,
    v.cvss_score AS our_cvss,
    v.severity AS our_severity,
    n.nvd_cvss_score AS nvd_cvss,
    n.nvd_severity,
    n.nvd_cvss_version,
    round(abs((v.cvss_score - n.nvd_cvss_score)), 1) AS cvss_abs_diff,
    abs((public.fn_severity_rank((v.severity)::text) - public.fn_severity_rank((n.nvd_severity)::text))) AS severity_gap,
    n.synced_at
   FROM (public.vulnerabilities v
     JOIN public.nvd_cve_details n ON (((n.cve_id)::text = (v.cve_id)::text)))
  WHERE (((n.nvd_status)::text = 'SYNCED'::text) AND (n.nvd_cvss_score IS NOT NULL) AND (((v.severity)::text IS DISTINCT FROM (n.nvd_severity)::text) OR (abs((v.cvss_score - n.nvd_cvss_score)) >= 0.5)));


--
-- Name: VIEW vw_cvss_nvd_mismatch; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.vw_cvss_nvd_mismatch IS '우리 DB 평가치(cvss_score/severity)와 NVD 공식값이 어긋나는 취약점 (severity 불일치 또는 CVSS 0.5점 이상 차이)';


--
-- Name: vw_cvss_severity_mismatch; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_cvss_severity_mismatch AS
 SELECT 'vulnerabilities'::text AS source_table,
    v.vuln_id AS record_id,
    v.cve_id AS ref_code,
    v.cvss_score,
    v.severity AS labeled_severity,
    public.fn_cvss_band(v.cvss_score) AS expected_severity,
    abs((public.fn_severity_rank((v.severity)::text) - public.fn_severity_rank(public.fn_cvss_band(v.cvss_score)))) AS severity_gap
   FROM public.vulnerabilities v
  WHERE ((v.cvss_score IS NOT NULL) AND ((v.severity)::text IS DISTINCT FROM public.fn_cvss_band(v.cvss_score)))
UNION ALL
 SELECT 'security_events'::text AS source_table,
    e.event_id AS record_id,
    (((a.asset_name)::text || ' / '::text) || (v.cve_id)::text) AS ref_code,
    v.cvss_score,
    e.severity AS labeled_severity,
    public.fn_cvss_band(v.cvss_score) AS expected_severity,
    abs((public.fn_severity_rank((e.severity)::text) - public.fn_severity_rank(public.fn_cvss_band(v.cvss_score)))) AS severity_gap
   FROM ((public.security_events e
     JOIN public.vulnerabilities v ON ((v.vuln_id = e.vuln_id)))
     JOIN public.assets a ON ((a.asset_id = e.asset_id)))
  WHERE ((v.cvss_score IS NOT NULL) AND ((e.severity)::text IS DISTINCT FROM public.fn_cvss_band(v.cvss_score)));


--
-- Name: VIEW vw_cvss_severity_mismatch; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.vw_cvss_severity_mismatch IS 'CVSS 점수로 산출한 등급과 severity 라벨이 불일치하는 이상 후보 (하드 제약 아님, 검토용)';


--
-- Name: vw_open_high_risk_events; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_open_high_risk_events AS
 SELECT e.event_id,
    a.asset_name,
    e.event_type,
    e.severity,
    e.detected_at
   FROM (public.security_events e
     JOIN public.assets a ON ((a.asset_id = e.asset_id)))
  WHERE (((e.status)::text <> 'RESOLVED'::text) AND ((e.severity)::text = ANY (ARRAY[('HIGH'::character varying)::text, ('CRITICAL'::character varying)::text])));


--
-- Name: vw_priority_vulnerabilities; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_priority_vulnerabilities AS
 SELECT v.vuln_id,
    v.cve_id,
    v.source,
    v.cvss_score,
    v.severity AS cvss_severity,
    n.epss_score,
    n.epss_percentile,
    round((v.cvss_score * n.epss_score), 3) AS priority_score,
        CASE
            WHEN (n.epss_percentile >= 0.99) THEN 'TOP 1%'::text
            WHEN (n.epss_percentile >= 0.95) THEN 'TOP 5%'::text
            WHEN (n.epss_percentile >= 0.90) THEN 'TOP 10%'::text
            WHEN (n.epss_percentile >= 0.75) THEN 'TOP 25%'::text
            ELSE '—'::text
        END AS epss_band,
    ((n.epss_percentile >= 0.90) AND ((v.severity)::text = ANY ((ARRAY['LOW'::character varying, 'MEDIUM'::character varying])::text[]))) AS epss_over_cvss,
    ( SELECT count(*) AS count
           FROM public.asset_vulnerabilities av
          WHERE ((av.vuln_id = v.vuln_id) AND ((av.status)::text = 'OPEN'::text))) AS open_on_assets
   FROM (public.vulnerabilities v
     JOIN public.nvd_cve_details n ON (((n.cve_id)::text = (v.cve_id)::text)))
  WHERE ((v.cve_id IS NOT NULL) AND (n.epss_score IS NOT NULL))
  ORDER BY ((n.epss_percentile >= 0.90) AND ((v.severity)::text = ANY ((ARRAY['LOW'::character varying, 'MEDIUM'::character varying])::text[]))) DESC, (round((v.cvss_score * n.epss_score), 3)) DESC, v.cvss_score DESC;


--
-- Name: VIEW vw_priority_vulnerabilities; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.vw_priority_vulnerabilities IS 'CVSS×EPSS 우선순위. priority_score = cvss_score × epss_score. epss_over_cvss=TRUE 는 CVSS 낮음+악용 상위10% (EPSS 를 쓰는 핵심 케이스).';


--
-- Name: alert_log alert_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_log ALTER COLUMN alert_id SET DEFAULT nextval('public.alert_log_alert_id_seq'::regclass);


--
-- Name: assets asset_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets ALTER COLUMN asset_id SET DEFAULT nextval('public.assets_asset_id_seq'::regclass);


--
-- Name: audit_log audit_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log ALTER COLUMN audit_id SET DEFAULT nextval('public.audit_log_audit_id_seq'::regclass);


--
-- Name: responses response_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.responses ALTER COLUMN response_id SET DEFAULT nextval('public.responses_response_id_seq'::regclass);


--
-- Name: scan_runs scan_run_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_runs ALTER COLUMN scan_run_id SET DEFAULT nextval('public.scan_runs_scan_run_id_seq'::regclass);


--
-- Name: security_events event_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events ALTER COLUMN event_id SET DEFAULT nextval('public.security_events_event_id_seq'::regclass);


--
-- Name: staff staff_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.staff ALTER COLUMN staff_id SET DEFAULT nextval('public.staff_staff_id_seq'::regclass);


--
-- Name: threat_reports report_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_reports ALTER COLUMN report_id SET DEFAULT nextval('public.threat_reports_report_id_seq'::regclass);


--
-- Name: vulnerabilities vuln_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities ALTER COLUMN vuln_id SET DEFAULT nextval('public.vulnerabilities_vuln_id_seq'::regclass);


--
-- Name: alert_log alert_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_log
    ADD CONSTRAINT alert_log_pkey PRIMARY KEY (alert_id);


--
-- Name: asset_vulnerabilities asset_vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_pkey PRIMARY KEY (asset_id, vuln_id);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (asset_id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (audit_id);


--
-- Name: departments departments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_pkey PRIMARY KEY (dept_name);


--
-- Name: event_types event_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_types
    ADD CONSTRAINT event_types_pkey PRIMARY KEY (event_type_name);


--
-- Name: nvd_cve_details nvd_cve_details_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nvd_cve_details
    ADD CONSTRAINT nvd_cve_details_pkey PRIMARY KEY (cve_id);


--
-- Name: nvd_watch_candidates nvd_watch_candidates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nvd_watch_candidates
    ADD CONSTRAINT nvd_watch_candidates_pkey PRIMARY KEY (cve_id);


--
-- Name: responses responses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.responses
    ADD CONSTRAINT responses_pkey PRIMARY KEY (response_id);


--
-- Name: rls_role_department rls_role_department_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rls_role_department
    ADD CONSTRAINT rls_role_department_pkey PRIMARY KEY (role_name);


--
-- Name: scan_runs scan_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_runs
    ADD CONSTRAINT scan_runs_pkey PRIMARY KEY (scan_run_id);


--
-- Name: scan_runs scan_runs_tool_target_hostname_scanned_at_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_runs
    ADD CONSTRAINT scan_runs_tool_target_hostname_scanned_at_key UNIQUE (tool, target_hostname, scanned_at);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: security_events security_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_pkey PRIMARY KEY (event_id);


--
-- Name: staff staff_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.staff
    ADD CONSTRAINT staff_pkey PRIMARY KEY (staff_id);


--
-- Name: threat_reports threat_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_reports
    ADD CONSTRAINT threat_reports_pkey PRIMARY KEY (report_id);


--
-- Name: alert_log uq_alert_log_dedup; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_log
    ADD CONSTRAINT uq_alert_log_dedup UNIQUE (alert_type, ref_key);


--
-- Name: vulnerabilities vulnerabilities_cve_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_cve_id_key UNIQUE (cve_id);


--
-- Name: vulnerabilities vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (vuln_id);


--
-- Name: idx_alert_log_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_log_created ON public.alert_log USING btree (created_at DESC);


--
-- Name: idx_alert_log_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_log_type ON public.alert_log USING btree (alert_type, created_at DESC);


--
-- Name: idx_asset_vulnerabilities_scan_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_vulnerabilities_scan_run_id ON public.asset_vulnerabilities USING btree (scan_run_id) WHERE (scan_run_id IS NOT NULL);


--
-- Name: idx_asset_vulnerabilities_vuln_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_vulnerabilities_vuln_id ON public.asset_vulnerabilities USING btree (vuln_id);


--
-- Name: idx_audit_log_table_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_table_time ON public.audit_log USING btree (table_name, changed_at DESC);


--
-- Name: idx_responses_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_responses_event_id ON public.responses USING btree (event_id);


--
-- Name: idx_responses_staff_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_responses_staff_id ON public.responses USING btree (staff_id);


--
-- Name: idx_security_events_asset_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_asset_id ON public.security_events USING btree (asset_id);


--
-- Name: idx_security_events_asset_id_detected_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_asset_id_detected_at ON public.security_events USING btree (asset_id, detected_at);


--
-- Name: idx_security_events_open_high_risk; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_open_high_risk ON public.security_events USING btree (severity, detected_at) WHERE ((status)::text <> 'RESOLVED'::text);


--
-- Name: idx_security_events_vuln_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_vuln_id ON public.security_events USING btree (vuln_id);


--
-- Name: idx_threat_reports_related_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_reports_related_event_id ON public.threat_reports USING btree (related_event_id) WHERE (related_event_id IS NOT NULL);


--
-- Name: idx_vulnerabilities_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_source ON public.vulnerabilities USING btree (source);


--
-- Name: mv_asset_risk_score_label_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mv_asset_risk_score_label_idx ON public.mv_asset_risk_score USING btree (risk_label, risk_score DESC);


--
-- Name: mv_asset_risk_score_pk; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mv_asset_risk_score_pk ON public.mv_asset_risk_score USING btree (asset_id);


--
-- Name: threat_reports_embedding_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX threat_reports_embedding_idx ON public.threat_reports USING hnsw (embedding public.vector_cosine_ops);


--
-- Name: uq_vulnerabilities_finding_ref; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_vulnerabilities_finding_ref ON public.vulnerabilities USING btree (finding_ref) WHERE (finding_ref IS NOT NULL);


--
-- Name: audit_log trg_audit_log_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_audit_log_no_truncate BEFORE TRUNCATE ON public.audit_log FOR EACH STATEMENT EXECUTE FUNCTION public.fn_audit_log_block_mutation();


--
-- Name: audit_log trg_audit_log_no_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_audit_log_no_update BEFORE DELETE OR UPDATE ON public.audit_log FOR EACH ROW EXECUTE FUNCTION public.fn_audit_log_block_mutation();


--
-- Name: responses trg_audit_responses; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_audit_responses AFTER INSERT OR DELETE OR UPDATE ON public.responses FOR EACH ROW EXECUTE FUNCTION public.fn_audit_row_change();


--
-- Name: security_events trg_audit_security_events; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_audit_security_events AFTER INSERT OR DELETE OR UPDATE ON public.security_events FOR EACH ROW EXECUTE FUNCTION public.fn_audit_row_change();


--
-- Name: responses trg_responses_time_check; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_responses_time_check BEFORE INSERT OR UPDATE ON public.responses FOR EACH ROW EXECUTE FUNCTION public.fn_validate_response_timing();


--
-- Name: asset_vulnerabilities asset_vulnerabilities_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(asset_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: asset_vulnerabilities asset_vulnerabilities_scan_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_scan_run_id_fkey FOREIGN KEY (scan_run_id) REFERENCES public.scan_runs(scan_run_id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: asset_vulnerabilities asset_vulnerabilities_vuln_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_vuln_id_fkey FOREIGN KEY (vuln_id) REFERENCES public.vulnerabilities(vuln_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: assets fk_assets_department; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT fk_assets_department FOREIGN KEY (department) REFERENCES public.departments(dept_name) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- Name: rls_role_department fk_rls_role_department_department; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rls_role_department
    ADD CONSTRAINT fk_rls_role_department_department FOREIGN KEY (department) REFERENCES public.departments(dept_name) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- Name: security_events fk_security_events_event_type; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT fk_security_events_event_type FOREIGN KEY (event_type) REFERENCES public.event_types(event_type_name) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- Name: staff fk_staff_department; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.staff
    ADD CONSTRAINT fk_staff_department FOREIGN KEY (department) REFERENCES public.departments(dept_name) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- Name: nvd_cve_details nvd_cve_details_cve_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nvd_cve_details
    ADD CONSTRAINT nvd_cve_details_cve_id_fkey FOREIGN KEY (cve_id) REFERENCES public.vulnerabilities(cve_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: responses responses_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.responses
    ADD CONSTRAINT responses_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.security_events(event_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: responses responses_staff_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.responses
    ADD CONSTRAINT responses_staff_id_fkey FOREIGN KEY (staff_id) REFERENCES public.staff(staff_id) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- Name: scan_runs scan_runs_target_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_runs
    ADD CONSTRAINT scan_runs_target_asset_id_fkey FOREIGN KEY (target_asset_id) REFERENCES public.assets(asset_id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: security_events security_events_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(asset_id) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- Name: security_events security_events_vuln_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_vuln_id_fkey FOREIGN KEY (vuln_id) REFERENCES public.vulnerabilities(vuln_id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: threat_reports threat_reports_related_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_reports
    ADD CONSTRAINT threat_reports_related_event_id_fkey FOREIGN KEY (related_event_id) REFERENCES public.security_events(event_id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: assets; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;

--
-- Name: assets p_assets_dept_scope; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY p_assets_dept_scope ON public.assets FOR SELECT TO dept_infra, dept_dev, dept_sales USING (((department)::text = COALESCE(NULLIF(current_setting('app.department'::text, true), ''::text), (( SELECT r.department
   FROM public.rls_role_department r
  WHERE (r.role_name = CURRENT_USER)))::text)));


--
-- Name: assets p_assets_rbac_all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY p_assets_rbac_all ON public.assets TO security_analyst, security_manager, security_admin USING (true) WITH CHECK (true);


--
-- Name: assets p_assets_svc_ingest; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY p_assets_svc_ingest ON public.assets FOR SELECT TO svc_event_ingest USING (true);


--
-- Name: security_events p_events_dept_scope; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY p_events_dept_scope ON public.security_events FOR SELECT TO dept_infra, dept_dev, dept_sales USING ((public.fn_asset_department(asset_id) = public.fn_current_dept()));


--
-- Name: security_events p_events_rbac_all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY p_events_rbac_all ON public.security_events TO security_analyst, security_manager, security_admin USING (true) WITH CHECK (true);


--
-- Name: security_events p_events_svc_ingest; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY p_events_svc_ingest ON public.security_events FOR INSERT TO svc_event_ingest WITH CHECK ((description ~~ '[SIM]%'::text));


--
-- Name: responses p_responses_dept_scope; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY p_responses_dept_scope ON public.responses FOR SELECT TO dept_infra, dept_dev, dept_sales USING ((public.fn_event_department(event_id) = public.fn_current_dept()));


--
-- Name: responses p_responses_rbac_all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY p_responses_rbac_all ON public.responses TO security_analyst, security_manager, security_admin USING (true) WITH CHECK (true);


--
-- Name: responses p_responses_svc_ingest; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY p_responses_svc_ingest ON public.responses FOR INSERT TO svc_event_ingest WITH CHECK ((action_taken ~~ '[SIM]%'::text));


--
-- Name: responses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.responses ENABLE ROW LEVEL SECURITY;

--
-- Name: security_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;

--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: -
--

GRANT USAGE ON SCHEMA public TO dept_infra;
GRANT USAGE ON SCHEMA public TO dept_dev;
GRANT USAGE ON SCHEMA public TO dept_sales;
GRANT USAGE ON SCHEMA public TO security_analyst;
GRANT USAGE ON SCHEMA public TO security_admin;
GRANT USAGE ON SCHEMA public TO security_manager;
GRANT USAGE ON SCHEMA public TO svc_event_ingest;


--
-- Name: FUNCTION halfvec_in(cstring, oid, integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_in(cstring, oid, integer) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_out(public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_out(public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_recv(internal, oid, integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_recv(internal, oid, integer) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_send(public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_send(public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_typmod_in(cstring[]); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_typmod_in(cstring[]) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_in(cstring, oid, integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_in(cstring, oid, integer) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_out(public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_out(public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_recv(internal, oid, integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_recv(internal, oid, integer) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_send(public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_send(public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_typmod_in(cstring[]); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_typmod_in(cstring[]) FROM PUBLIC;


--
-- Name: FUNCTION vector_in(cstring, oid, integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_in(cstring, oid, integer) FROM PUBLIC;


--
-- Name: FUNCTION vector_out(public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_out(public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_recv(internal, oid, integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_recv(internal, oid, integer) FROM PUBLIC;


--
-- Name: FUNCTION vector_send(public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_send(public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_typmod_in(cstring[]); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_typmod_in(cstring[]) FROM PUBLIC;


--
-- Name: FUNCTION array_to_halfvec(real[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_halfvec(real[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION array_to_sparsevec(real[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_sparsevec(real[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION array_to_vector(real[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_vector(real[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION array_to_halfvec(double precision[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_halfvec(double precision[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION array_to_sparsevec(double precision[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_sparsevec(double precision[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION array_to_vector(double precision[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_vector(double precision[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION array_to_halfvec(integer[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_halfvec(integer[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION array_to_sparsevec(integer[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_sparsevec(integer[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION array_to_vector(integer[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_vector(integer[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION array_to_halfvec(numeric[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_halfvec(numeric[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION array_to_sparsevec(numeric[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_sparsevec(numeric[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION array_to_vector(numeric[], integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.array_to_vector(numeric[], integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_to_float4(public.halfvec, integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_to_float4(public.halfvec, integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION halfvec(public.halfvec, integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec(public.halfvec, integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_to_sparsevec(public.halfvec, integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_to_sparsevec(public.halfvec, integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_to_vector(public.halfvec, integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_to_vector(public.halfvec, integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_to_halfvec(public.sparsevec, integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_to_halfvec(public.sparsevec, integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec(public.sparsevec, integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec(public.sparsevec, integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_to_vector(public.sparsevec, integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_to_vector(public.sparsevec, integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION vector_to_float4(public.vector, integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_to_float4(public.vector, integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION vector_to_halfvec(public.vector, integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_to_halfvec(public.vector, integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION vector_to_sparsevec(public.vector, integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_to_sparsevec(public.vector, integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION vector(public.vector, integer, boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector(public.vector, integer, boolean) FROM PUBLIC;


--
-- Name: FUNCTION binary_quantize(public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.binary_quantize(public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION binary_quantize(public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.binary_quantize(public.vector) FROM PUBLIC;


--
-- Name: FUNCTION cosine_distance(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.cosine_distance(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION cosine_distance(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.cosine_distance(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION cosine_distance(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.cosine_distance(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION fn_archive_audit_log(p_retention interval); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.fn_archive_audit_log(p_retention interval) FROM PUBLIC;
GRANT ALL ON FUNCTION public.fn_archive_audit_log(p_retention interval) TO security_admin;


--
-- Name: FUNCTION fn_asset_department(p_asset_id integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.fn_asset_department(p_asset_id integer) FROM PUBLIC;
GRANT ALL ON FUNCTION public.fn_asset_department(p_asset_id integer) TO security_analyst;
GRANT ALL ON FUNCTION public.fn_asset_department(p_asset_id integer) TO security_admin;
GRANT ALL ON FUNCTION public.fn_asset_department(p_asset_id integer) TO security_manager;
GRANT ALL ON FUNCTION public.fn_asset_department(p_asset_id integer) TO dept_infra;
GRANT ALL ON FUNCTION public.fn_asset_department(p_asset_id integer) TO dept_dev;
GRANT ALL ON FUNCTION public.fn_asset_department(p_asset_id integer) TO dept_sales;


--
-- Name: FUNCTION fn_audit_log_block_mutation(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.fn_audit_log_block_mutation() FROM PUBLIC;


--
-- Name: FUNCTION fn_audit_row_change(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.fn_audit_row_change() FROM PUBLIC;


--
-- Name: FUNCTION fn_current_dept(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.fn_current_dept() FROM PUBLIC;
GRANT ALL ON FUNCTION public.fn_current_dept() TO security_analyst;
GRANT ALL ON FUNCTION public.fn_current_dept() TO security_admin;
GRANT ALL ON FUNCTION public.fn_current_dept() TO security_manager;
GRANT ALL ON FUNCTION public.fn_current_dept() TO dept_infra;
GRANT ALL ON FUNCTION public.fn_current_dept() TO dept_dev;
GRANT ALL ON FUNCTION public.fn_current_dept() TO dept_sales;


--
-- Name: FUNCTION fn_cvss_band(p_score numeric); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.fn_cvss_band(p_score numeric) FROM PUBLIC;
GRANT ALL ON FUNCTION public.fn_cvss_band(p_score numeric) TO security_analyst;
GRANT ALL ON FUNCTION public.fn_cvss_band(p_score numeric) TO security_admin;
GRANT ALL ON FUNCTION public.fn_cvss_band(p_score numeric) TO security_manager;


--
-- Name: FUNCTION fn_event_department(p_event_id integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.fn_event_department(p_event_id integer) FROM PUBLIC;
GRANT ALL ON FUNCTION public.fn_event_department(p_event_id integer) TO security_analyst;
GRANT ALL ON FUNCTION public.fn_event_department(p_event_id integer) TO security_admin;
GRANT ALL ON FUNCTION public.fn_event_department(p_event_id integer) TO security_manager;
GRANT ALL ON FUNCTION public.fn_event_department(p_event_id integer) TO dept_infra;
GRANT ALL ON FUNCTION public.fn_event_department(p_event_id integer) TO dept_dev;
GRANT ALL ON FUNCTION public.fn_event_department(p_event_id integer) TO dept_sales;


--
-- Name: FUNCTION fn_refresh_risk_score(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.fn_refresh_risk_score() FROM PUBLIC;
GRANT ALL ON FUNCTION public.fn_refresh_risk_score() TO security_admin;


--
-- Name: FUNCTION fn_severity_rank(p_label text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.fn_severity_rank(p_label text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.fn_severity_rank(p_label text) TO security_analyst;
GRANT ALL ON FUNCTION public.fn_severity_rank(p_label text) TO security_admin;
GRANT ALL ON FUNCTION public.fn_severity_rank(p_label text) TO security_manager;


--
-- Name: FUNCTION fn_validate_response_timing(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.fn_validate_response_timing() FROM PUBLIC;


--
-- Name: FUNCTION fn_verify_audit_chain(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.fn_verify_audit_chain() FROM PUBLIC;
GRANT ALL ON FUNCTION public.fn_verify_audit_chain() TO security_admin;
GRANT ALL ON FUNCTION public.fn_verify_audit_chain() TO security_manager;
GRANT ALL ON FUNCTION public.fn_verify_audit_chain() TO security_analyst;


--
-- Name: FUNCTION halfvec_accum(double precision[], public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_accum(double precision[], public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_add(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_add(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_avg(double precision[]); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_avg(double precision[]) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_cmp(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_cmp(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_combine(double precision[], double precision[]); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_combine(double precision[], double precision[]) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_concat(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_concat(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_eq(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_eq(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_ge(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_ge(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_gt(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_gt(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_l2_squared_distance(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_l2_squared_distance(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_le(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_le(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_lt(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_lt(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_mul(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_mul(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_ne(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_ne(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_negative_inner_product(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_negative_inner_product(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_spherical_distance(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_spherical_distance(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION halfvec_sub(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.halfvec_sub(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION hamming_distance(bit, bit); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.hamming_distance(bit, bit) FROM PUBLIC;


--
-- Name: FUNCTION hnsw_bit_support(internal); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.hnsw_bit_support(internal) FROM PUBLIC;


--
-- Name: FUNCTION hnsw_halfvec_support(internal); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.hnsw_halfvec_support(internal) FROM PUBLIC;


--
-- Name: FUNCTION hnsw_sparsevec_support(internal); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.hnsw_sparsevec_support(internal) FROM PUBLIC;


--
-- Name: FUNCTION hnswhandler(internal); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.hnswhandler(internal) FROM PUBLIC;


--
-- Name: FUNCTION inner_product(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.inner_product(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION inner_product(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.inner_product(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION inner_product(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.inner_product(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION ivfflat_bit_support(internal); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.ivfflat_bit_support(internal) FROM PUBLIC;


--
-- Name: FUNCTION ivfflat_halfvec_support(internal); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.ivfflat_halfvec_support(internal) FROM PUBLIC;


--
-- Name: FUNCTION ivfflathandler(internal); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.ivfflathandler(internal) FROM PUBLIC;


--
-- Name: FUNCTION jaccard_distance(bit, bit); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.jaccard_distance(bit, bit) FROM PUBLIC;


--
-- Name: FUNCTION l1_distance(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.l1_distance(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION l1_distance(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.l1_distance(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION l1_distance(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.l1_distance(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION l2_distance(public.halfvec, public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.l2_distance(public.halfvec, public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION l2_distance(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.l2_distance(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION l2_distance(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.l2_distance(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION l2_norm(public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.l2_norm(public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION l2_norm(public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.l2_norm(public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION l2_normalize(public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.l2_normalize(public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION l2_normalize(public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.l2_normalize(public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION l2_normalize(public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.l2_normalize(public.vector) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_cmp(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_cmp(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_eq(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_eq(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_ge(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_ge(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_gt(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_gt(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_l2_squared_distance(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_l2_squared_distance(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_le(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_le(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_lt(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_lt(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_ne(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_ne(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION sparsevec_negative_inner_product(public.sparsevec, public.sparsevec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sparsevec_negative_inner_product(public.sparsevec, public.sparsevec) FROM PUBLIC;


--
-- Name: FUNCTION subvector(public.halfvec, integer, integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.subvector(public.halfvec, integer, integer) FROM PUBLIC;


--
-- Name: FUNCTION subvector(public.vector, integer, integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.subvector(public.vector, integer, integer) FROM PUBLIC;


--
-- Name: FUNCTION vector_accum(double precision[], public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_accum(double precision[], public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_add(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_add(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_avg(double precision[]); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_avg(double precision[]) FROM PUBLIC;


--
-- Name: FUNCTION vector_cmp(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_cmp(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_combine(double precision[], double precision[]); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_combine(double precision[], double precision[]) FROM PUBLIC;


--
-- Name: FUNCTION vector_concat(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_concat(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_dims(public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_dims(public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION vector_dims(public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_dims(public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_eq(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_eq(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_ge(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_ge(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_gt(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_gt(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_l2_squared_distance(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_l2_squared_distance(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_le(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_le(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_lt(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_lt(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_mul(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_mul(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_ne(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_ne(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_negative_inner_product(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_negative_inner_product(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_norm(public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_norm(public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_spherical_distance(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_spherical_distance(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION vector_sub(public.vector, public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.vector_sub(public.vector, public.vector) FROM PUBLIC;


--
-- Name: FUNCTION avg(public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.avg(public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION avg(public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.avg(public.vector) FROM PUBLIC;


--
-- Name: FUNCTION sum(public.halfvec); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sum(public.halfvec) FROM PUBLIC;


--
-- Name: FUNCTION sum(public.vector); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.sum(public.vector) FROM PUBLIC;


--
-- Name: TABLE alert_log; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.alert_log TO security_analyst;
GRANT ALL ON TABLE public.alert_log TO security_admin;
GRANT SELECT ON TABLE public.alert_log TO security_manager;


--
-- Name: SEQUENCE alert_log_alert_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.alert_log_alert_id_seq TO security_admin;


--
-- Name: TABLE asset_vulnerabilities; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.asset_vulnerabilities TO security_admin;
GRANT SELECT ON TABLE public.asset_vulnerabilities TO security_manager;
GRANT SELECT ON TABLE public.asset_vulnerabilities TO security_analyst;


--
-- Name: TABLE assets; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.assets TO security_admin;
GRANT SELECT ON TABLE public.assets TO security_manager;
GRANT SELECT ON TABLE public.assets TO security_analyst;


--
-- Name: COLUMN assets.asset_id; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(asset_id) ON TABLE public.assets TO dept_infra;
GRANT SELECT(asset_id) ON TABLE public.assets TO dept_dev;
GRANT SELECT(asset_id) ON TABLE public.assets TO dept_sales;
GRANT SELECT(asset_id) ON TABLE public.assets TO svc_event_ingest;


--
-- Name: COLUMN assets.asset_name; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(asset_name) ON TABLE public.assets TO dept_infra;
GRANT SELECT(asset_name) ON TABLE public.assets TO dept_dev;
GRANT SELECT(asset_name) ON TABLE public.assets TO dept_sales;
GRANT SELECT(asset_name) ON TABLE public.assets TO svc_event_ingest;


--
-- Name: COLUMN assets.asset_type; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(asset_type) ON TABLE public.assets TO dept_infra;
GRANT SELECT(asset_type) ON TABLE public.assets TO dept_dev;
GRANT SELECT(asset_type) ON TABLE public.assets TO dept_sales;


--
-- Name: COLUMN assets.department; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(department) ON TABLE public.assets TO dept_infra;
GRANT SELECT(department) ON TABLE public.assets TO dept_dev;
GRANT SELECT(department) ON TABLE public.assets TO dept_sales;
GRANT SELECT(department) ON TABLE public.assets TO svc_event_ingest;


--
-- Name: COLUMN assets.importance_level; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(importance_level) ON TABLE public.assets TO dept_infra;
GRANT SELECT(importance_level) ON TABLE public.assets TO dept_dev;
GRANT SELECT(importance_level) ON TABLE public.assets TO dept_sales;


--
-- Name: COLUMN assets.created_at; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(created_at) ON TABLE public.assets TO dept_infra;
GRANT SELECT(created_at) ON TABLE public.assets TO dept_dev;
GRANT SELECT(created_at) ON TABLE public.assets TO dept_sales;


--
-- Name: SEQUENCE assets_asset_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.assets_asset_id_seq TO security_admin;


--
-- Name: TABLE audit_log; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT ON TABLE public.audit_log TO security_admin;
GRANT SELECT,INSERT ON TABLE public.audit_log TO security_manager;
GRANT SELECT,INSERT ON TABLE public.audit_log TO security_analyst;
GRANT INSERT ON TABLE public.audit_log TO dept_infra;
GRANT INSERT ON TABLE public.audit_log TO dept_dev;
GRANT INSERT ON TABLE public.audit_log TO dept_sales;


--
-- Name: SEQUENCE audit_log_audit_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.audit_log_audit_id_seq TO security_admin;


--
-- Name: TABLE audit_log_archive; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,REFERENCES,TRIGGER ON TABLE public.audit_log_archive TO security_admin;
GRANT SELECT ON TABLE public.audit_log_archive TO security_manager;


--
-- Name: TABLE departments; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.departments TO security_analyst;
GRANT ALL ON TABLE public.departments TO security_admin;
GRANT SELECT ON TABLE public.departments TO security_manager;


--
-- Name: TABLE event_types; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.event_types TO security_analyst;
GRANT ALL ON TABLE public.event_types TO security_admin;
GRANT SELECT ON TABLE public.event_types TO security_manager;
GRANT SELECT ON TABLE public.event_types TO dept_infra;
GRANT SELECT ON TABLE public.event_types TO dept_dev;
GRANT SELECT ON TABLE public.event_types TO dept_sales;
GRANT SELECT ON TABLE public.event_types TO svc_event_ingest;


--
-- Name: TABLE vulnerabilities; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.vulnerabilities TO security_admin;
GRANT SELECT ON TABLE public.vulnerabilities TO security_manager;
GRANT SELECT ON TABLE public.vulnerabilities TO security_analyst;


--
-- Name: TABLE mv_asset_risk_score; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.mv_asset_risk_score TO security_analyst;
GRANT ALL ON TABLE public.mv_asset_risk_score TO security_admin;
GRANT SELECT ON TABLE public.mv_asset_risk_score TO security_manager;


--
-- Name: TABLE nvd_cve_details; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.nvd_cve_details TO security_analyst;
GRANT ALL ON TABLE public.nvd_cve_details TO security_admin;
GRANT SELECT ON TABLE public.nvd_cve_details TO security_manager;


--
-- Name: TABLE nvd_watch_candidates; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.nvd_watch_candidates TO security_analyst;
GRANT ALL ON TABLE public.nvd_watch_candidates TO security_admin;
GRANT SELECT ON TABLE public.nvd_watch_candidates TO security_manager;


--
-- Name: TABLE responses; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.responses TO security_admin;
GRANT SELECT ON TABLE public.responses TO security_manager;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.responses TO security_analyst;
GRANT SELECT ON TABLE public.responses TO dept_infra;
GRANT SELECT ON TABLE public.responses TO dept_dev;
GRANT SELECT ON TABLE public.responses TO dept_sales;
GRANT INSERT ON TABLE public.responses TO svc_event_ingest;


--
-- Name: SEQUENCE responses_response_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.responses_response_id_seq TO security_admin;
GRANT SELECT,USAGE ON SEQUENCE public.responses_response_id_seq TO security_analyst;
GRANT SELECT,USAGE ON SEQUENCE public.responses_response_id_seq TO svc_event_ingest;


--
-- Name: TABLE rls_role_department; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.rls_role_department TO dept_infra;
GRANT SELECT ON TABLE public.rls_role_department TO dept_dev;
GRANT SELECT ON TABLE public.rls_role_department TO dept_sales;
GRANT ALL ON TABLE public.rls_role_department TO security_admin;
GRANT SELECT ON TABLE public.rls_role_department TO security_manager;
GRANT SELECT ON TABLE public.rls_role_department TO security_analyst;


--
-- Name: TABLE scan_runs; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.scan_runs TO security_analyst;
GRANT ALL ON TABLE public.scan_runs TO security_admin;
GRANT SELECT ON TABLE public.scan_runs TO security_manager;


--
-- Name: SEQUENCE scan_runs_scan_run_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.scan_runs_scan_run_id_seq TO security_admin;


--
-- Name: TABLE schema_migrations; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.schema_migrations TO security_analyst;
GRANT ALL ON TABLE public.schema_migrations TO security_admin;
GRANT SELECT ON TABLE public.schema_migrations TO security_manager;


--
-- Name: TABLE security_events; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.security_events TO security_admin;
GRANT SELECT ON TABLE public.security_events TO security_manager;
GRANT SELECT ON TABLE public.security_events TO security_analyst;
GRANT SELECT ON TABLE public.security_events TO dept_infra;
GRANT SELECT ON TABLE public.security_events TO dept_dev;
GRANT SELECT ON TABLE public.security_events TO dept_sales;
GRANT INSERT ON TABLE public.security_events TO svc_event_ingest;


--
-- Name: SEQUENCE security_events_event_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.security_events_event_id_seq TO security_admin;
GRANT SELECT,USAGE ON SEQUENCE public.security_events_event_id_seq TO svc_event_ingest;


--
-- Name: TABLE staff; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.staff TO security_admin;
GRANT SELECT ON TABLE public.staff TO security_manager;
GRANT SELECT ON TABLE public.staff TO security_analyst;


--
-- Name: COLUMN staff.staff_id; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(staff_id) ON TABLE public.staff TO svc_event_ingest;


--
-- Name: COLUMN staff.staff_name; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(staff_name) ON TABLE public.staff TO svc_event_ingest;


--
-- Name: SEQUENCE staff_staff_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.staff_staff_id_seq TO security_admin;


--
-- Name: TABLE threat_reports; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.threat_reports TO security_admin;
GRANT SELECT ON TABLE public.threat_reports TO security_manager;
GRANT SELECT ON TABLE public.threat_reports TO security_analyst;


--
-- Name: SEQUENCE threat_reports_report_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.threat_reports_report_id_seq TO security_admin;


--
-- Name: SEQUENCE vulnerabilities_vuln_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.vulnerabilities_vuln_id_seq TO security_admin;


--
-- Name: TABLE vw_asset_risk_score; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.vw_asset_risk_score TO security_admin;
GRANT SELECT ON TABLE public.vw_asset_risk_score TO security_manager;
GRANT SELECT ON TABLE public.vw_asset_risk_score TO security_analyst;


--
-- Name: TABLE vw_asset_vuln_summary; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.vw_asset_vuln_summary TO security_admin;
GRANT SELECT ON TABLE public.vw_asset_vuln_summary TO security_manager;
GRANT SELECT ON TABLE public.vw_asset_vuln_summary TO security_analyst;


--
-- Name: TABLE vw_assets_dept; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.vw_assets_dept TO security_analyst;
GRANT ALL ON TABLE public.vw_assets_dept TO security_admin;
GRANT SELECT ON TABLE public.vw_assets_dept TO security_manager;
GRANT SELECT ON TABLE public.vw_assets_dept TO dept_infra;
GRANT SELECT ON TABLE public.vw_assets_dept TO dept_dev;
GRANT SELECT ON TABLE public.vw_assets_dept TO dept_sales;


--
-- Name: TABLE vw_cvss_nvd_mismatch; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.vw_cvss_nvd_mismatch TO security_analyst;
GRANT ALL ON TABLE public.vw_cvss_nvd_mismatch TO security_admin;
GRANT SELECT ON TABLE public.vw_cvss_nvd_mismatch TO security_manager;


--
-- Name: TABLE vw_cvss_severity_mismatch; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.vw_cvss_severity_mismatch TO security_analyst;
GRANT ALL ON TABLE public.vw_cvss_severity_mismatch TO security_admin;
GRANT SELECT ON TABLE public.vw_cvss_severity_mismatch TO security_manager;


--
-- Name: TABLE vw_open_high_risk_events; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.vw_open_high_risk_events TO security_analyst;
GRANT ALL ON TABLE public.vw_open_high_risk_events TO security_admin;
GRANT SELECT ON TABLE public.vw_open_high_risk_events TO security_manager;


--
-- Name: TABLE vw_priority_vulnerabilities; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.vw_priority_vulnerabilities TO security_analyst;
GRANT ALL ON TABLE public.vw_priority_vulnerabilities TO security_admin;
GRANT SELECT ON TABLE public.vw_priority_vulnerabilities TO security_manager;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE summer IN SCHEMA public GRANT ALL ON SEQUENCES  TO security_admin;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE summer IN SCHEMA public GRANT SELECT ON TABLES  TO security_analyst;
ALTER DEFAULT PRIVILEGES FOR ROLE summer IN SCHEMA public GRANT ALL ON TABLES  TO security_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE summer IN SCHEMA public GRANT SELECT ON TABLES  TO security_manager;


--
-- PostgreSQL database dump complete
--

\unrestrict B8VbOjfHSaVolqqL2rtkPDG9Tug4odG0yKAaw0QGaaKiVdj00owxVI65wduXuxH

