import pandas as pd
import os
import json
from schemas import AuditResult, DeletionStatus, Step, Phase
from identity_resolver import build_identity_graph
from state_evaluator import get_state_at_audit_time
from evidence_parser import parse_evidence_file


def run_audit():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_dir = os.path.join(project_root, "dataset")

    requests_path = os.path.join(dataset_dir, "deletion_requests.csv")
    activity_path = os.path.join(dataset_dir, "system_activity.csv")
    rules_path = os.path.join(dataset_dir, "deletion_rules.csv")
    evidence_index_path = os.path.join(dataset_dir, "evidence_files.csv")
    output_path = os.path.join(dataset_dir, "output.csv")

    print("Building primary identity graph...")
    identity_map = build_identity_graph(dataset_dir)

    print("Loading datasets...")
    requests_df = pd.read_csv(requests_path)
    activity_df = pd.read_csv(activity_path)
    rules_df = pd.read_csv(rules_path)
    evidence_df = pd.read_csv(evidence_index_path)

    # Clean the resource_ids
    activity_df['resource_id'] = activity_df['resource_id'].astype(str).str.replace(r'\.0$', '', regex=True).str.strip()
    rules_map = dict(zip(rules_df['data_category'].str.upper(), rules_df['required_action'].str.upper()))

    results = []
    stats = {"total_applicable": 0, "found_in_identity_map": 0, "found_in_activity_logs": 0, "flagged_incomplete": 0}

    # Isolate mapping events to dynamically link 'user_01' to 'search_9729'
    link_events = activity_df[activity_df['event_type'] == 'LINK_RESOURCE_IDENTITY'].copy()

    print(f"Processing {len(requests_df)} requests...")
    for index, row in requests_df.iterrows():
        case_id = row['case_id']
        email = str(row['email']).strip().lower()
        audit_at = row['audit_at']
        request_text = str(row['request_text']).lower()

        if "delete" not in request_text and "remove" not in request_text and "erase" not in request_text:
            results.append(AuditResult(case_id=case_id, deletion_status=DeletionStatus.NOT_APPLICABLE, steps_json=[]))
            continue

        stats["total_applicable"] += 1

        # Get primary user_ids (e.g., 'user_01')
        raw_user_ids = identity_map.get(email, set())
        primary_user_ids = [str(uid).replace('.0', '').strip() for uid in raw_user_ids]

        if not primary_user_ids:
            results.append(AuditResult(case_id=case_id, deletion_status=DeletionStatus.COMPLETE, steps_json=[]))
            continue

        stats["found_in_identity_map"] += 1

        # CRITICAL FIX: Expand identities dynamically by checking the details column for the primary ID
        extended_user_ids = set(primary_user_ids)
        for uid in primary_user_ids:
            for _, link_row in link_events.iterrows():
                details_str = str(link_row.get('details', ''))
                # If 'user_01' is mentioned in the details of a LINK event, the resource_id belongs to them
                if uid in details_str:
                    extended_user_ids.add(str(link_row['resource_id']).strip())

        user_activity = activity_df[activity_df['resource_id'].isin(extended_user_ids)].copy()

        if not user_activity.empty:
            stats["found_in_activity_logs"] += 1

        final_state_df = get_state_at_audit_time(user_activity, audit_at)

        steps = []
        is_incomplete = False

        system_states = final_state_df.groupby('target_system')

        for target_sys, sys_events in system_states:
            target_sys = str(target_sys).upper()
            sys_event_types = sys_events['event_type'].tolist()
            sys_results = sys_events['reported_result'].tolist()
            event_status = dict(zip(sys_event_types, sys_results))
            res_id = sys_events.iloc[-1]['resource_id']

            is_deleted = event_status.get('DELETE_RECORD') == 'SUCCESS' or \
                         event_status.get('ANONYMIZE_RECORD') == 'SUCCESS' or \
                         event_status.get('REDACT_RECORD') == 'SUCCESS'

            if is_deleted:
                continue

            if ('SYNC_RECORD' in event_status and event_status['SYNC_RECORD'] in ['SUCCESS', 'PARTIAL']) or \
                    ('CREATE_EXPORT' in event_status and event_status['CREATE_EXPORT'] in ['SUCCESS', 'PARTIAL']):
                is_incomplete = True
                steps.append(Step(step_no=0, phase=Phase.FINDING, system_id=target_sys, resource_id=res_id,
                                  operation="REPORT_ACTIVE_DATA_FLOW", state="ACTIVE", evidence_id=""))
                steps.append(Step(step_no=0, phase=Phase.REMEDIATION, system_id=target_sys, resource_id=res_id,
                                  operation="DISABLE_DATA_FLOW", state="DISABLED", evidence_id=""))
                steps.append(Step(step_no=0, phase=Phase.VERIFICATION, system_id=target_sys, resource_id=res_id,
                                  operation="VERIFY_DATA_FLOW_DISABLED", state="DISABLED", evidence_id=""))

            if ('INDEX_RECORD' in event_status and event_status['INDEX_RECORD'] in ['SUCCESS', 'PARTIAL']) or \
                    ('UPDATE_RECORD' in event_status and event_status['UPDATE_RECORD'] in ['SUCCESS', 'PARTIAL']) or \
                    ('RETAIN_RECORD' in event_status and event_status['RETAIN_RECORD'] in ['SUCCESS', 'PARTIAL']):
                is_incomplete = True
                action = rules_map.get(target_sys, 'DELETE')

                if action in ['REDACT', 'TOMBSTONE']:
                    steps.append(Step(step_no=0, phase=Phase.FINDING, system_id=target_sys, resource_id=res_id,
                                      operation="REPORT_EXPOSED_PII", state="ACTIVE", evidence_id=""))
                    steps.append(Step(step_no=0, phase=Phase.REMEDIATION, system_id=target_sys, resource_id=res_id,
                                      operation="REDACT_RECORD", state="REDACTED", evidence_id=""))
                    steps.append(Step(step_no=0, phase=Phase.VERIFICATION, system_id=target_sys, resource_id=res_id,
                                      operation="VERIFY_RECORD_REDACTED", state="REDACTED", evidence_id=""))
                else:
                    steps.append(Step(step_no=0, phase=Phase.FINDING, system_id=target_sys, resource_id=res_id,
                                      operation="REPORT_REMAINING_RECORD", state="ACTIVE", evidence_id=""))
                    steps.append(Step(step_no=0, phase=Phase.REMEDIATION, system_id=target_sys, resource_id=res_id,
                                      operation="DELETE_RECORD", state="DELETED", evidence_id=""))
                    steps.append(Step(step_no=0, phase=Phase.VERIFICATION, system_id=target_sys, resource_id=res_id,
                                      operation="VERIFY_RECORD_ABSENT", state="DELETED", evidence_id=""))

        if extended_user_ids:
            target_id_for_llm = primary_user_ids[0] if primary_user_ids else list(extended_user_ids)[0]
            active_systems = final_state_df['target_system'].unique()
            relevant_evidence = evidence_df[evidence_df['origin'].isin(active_systems)]

            for _, ev_row in relevant_evidence.iterrows():
                file_path = os.path.join(dataset_dir, ev_row['file_path'])
                file_id = ev_row['file_id']
                sys_id = ev_row['origin']

                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    llm_result = parse_evidence_file(content, target_id_for_llm, file_id)

                    if llm_result and llm_result.get("exposed_fields"):
                        is_incomplete = True
                        steps.append(
                            Step(step_no=0, phase=Phase.FINDING, system_id=sys_id, resource_id=target_id_for_llm,
                                 operation="REPORT_EXPOSED_PII", state="EXPOSED", evidence_id=file_id))
                        steps.append(
                            Step(step_no=0, phase=Phase.REMEDIATION, system_id=sys_id, resource_id=target_id_for_llm,
                                 operation="REDACT_RECORD", state="REDACTED", evidence_id=""))
                        steps.append(
                            Step(step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=target_id_for_llm,
                                 operation="VERIFY_RECORD_REDACTED", state="REDACTED", evidence_id=""))

        if is_incomplete:
            stats["flagged_incomplete"] += 1

        status = DeletionStatus.INCOMPLETE if is_incomplete else DeletionStatus.COMPLETE
        audit_result = AuditResult(case_id=case_id, deletion_status=status, steps_json=steps)
        audit_result.sort_steps()
        results.append(audit_result)

    print("\n--- FINAL DIAGNOSTICS ---")
    print(f"Applicable Requests: {stats['total_applicable']}")
    print(f"Users found in Identity Graph: {stats['found_in_identity_map']}")
    print(f"Users found in System Logs (Mapped): {stats['found_in_activity_logs']}")
    print(f"Cases Flagged Incomplete: {stats['flagged_incomplete']}")
    print("-------------------------\n")

    print(f"Writing results to {output_path}...")
    output_data = [{"case_id": r.case_id, "deletion_status": r.deletion_status.value,
                    "steps_json": json.dumps([s.model_dump() for s in r.steps_json])} for r in results]
    pd.DataFrame(output_data).to_csv(output_path, index=False, quoting=1)

    print("Audit evaluation complete!")


if __name__ == "__main__":
    run_audit()