import pandas as pd


def get_state_at_audit_time(system_activity_df, audit_at_timestamp):
    """
    Replays the event log to determine the final state of a resource at the exact audit time.
    """
    # Added utc=True to normalize both datetimes to the same timezone format
    system_activity_df['event_time'] = pd.to_datetime(system_activity_df['event_time'], utc=True)
    audit_time = pd.to_datetime(audit_at_timestamp, utc=True)

    past_events = system_activity_df[system_activity_df['event_time'] <= audit_time]
    sorted_events = past_events.sort_values(by='event_time', ascending=True)

    final_state = sorted_events.drop_duplicates(
        subset=['target_system', 'resource_id', 'event_type'],
        keep='last'
    )

    return final_state