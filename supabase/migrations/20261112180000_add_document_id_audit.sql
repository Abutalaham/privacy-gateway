alter table public.audit_log
    add column if not exists document_id text not null default '';

create or replace function public.append_audit_record(p_record jsonb)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    current_head text;
begin
    perform pg_advisory_xact_lock(174731, 1);

    select record_hash
      into current_head
      from public.audit_log
     order by id desc
     limit 1;

    if coalesce(current_head, 'GENESIS') is distinct from (p_record ->> 'prev_hash') then
        raise exception using
            errcode = '40001',
            message = 'AUDIT_CHAIN_HEAD_MISMATCH';
    end if;

    insert into public.audit_log (
        request_id, document_id, created_at, purpose, doc_type, task, status, entity_types,
        placeholders, provider, model, external, fallback_used, outbound_payload,
        outbound_sha256, leak_check, attempts, timings, detection_engine, error,
        prev_hash, record_hash
    ) values (
        p_record ->> 'request_id', coalesce(p_record ->> 'document_id', ''),
        p_record ->> 'created_at', p_record ->> 'purpose', p_record ->> 'doc_type',
        p_record ->> 'task', p_record ->> 'status', p_record ->> 'entity_types',
        p_record ->> 'placeholders', p_record ->> 'provider', p_record ->> 'model',
        p_record ->> 'external', p_record ->> 'fallback_used', p_record ->> 'outbound_payload',
        p_record ->> 'outbound_sha256', p_record ->> 'leak_check', p_record ->> 'attempts',
        p_record ->> 'timings', p_record ->> 'detection_engine', p_record ->> 'error',
        p_record ->> 'prev_hash', p_record ->> 'record_hash'
    );
end;
$$;
