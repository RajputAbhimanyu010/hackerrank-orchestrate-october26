import pandas as pd
import os


def build_identity_graph(dataset_path="dataset"):
    """
    Parses user_identities.csv and user_audit_log.csv to map emails to all historical IDs.
    """
    identities_path = os.path.join(dataset_path, "user_identities.csv")
    audit_log_path = os.path.join(dataset_path, "user_audit_log.csv")

    try:
        identities_df = pd.read_csv(identities_path)
        audit_df = pd.read_csv(audit_log_path)

        identity_map = {}

        def add_mapping(email, user_id):
            if pd.isna(email) or pd.isna(user_id):
                return
            email = str(email).strip().lower()
            if email not in identity_map:
                identity_map[email] = set()
            identity_map[email].add(str(user_id).strip())

        for _, row in identities_df.iterrows():
            add_mapping(row['email'], row['user_id'])

        email_changes = audit_df[audit_df['field_name'] == 'email']
        for _, row in email_changes.iterrows():
            add_mapping(row['old_value'], row['user_id'])
            add_mapping(row['new_value'], row['user_id'])

        return identity_map

    except Exception as e:
        print(f"Error processing data: {e}")
        return None