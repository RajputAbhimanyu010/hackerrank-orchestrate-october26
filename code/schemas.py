from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum


class DeletionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Phase(str, Enum):
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class Step(BaseModel):
    step_no: int
    phase: Phase
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: Optional[str] = ""


class AuditResult(BaseModel):
    case_id: str
    deletion_status: DeletionStatus
    steps_json: List[Step] = Field(default_factory=list)

    def sort_steps(self):
        """
        Sorts steps strictly by: Phase -> Operation -> system_id -> resource_id
        """
        phase_order = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}

        op_order = {
            "REPORT_REMAINING_RECORD": 1, "REPORT_EXPOSED_PII": 2,
            "REPORT_ACTIVE_DATA_FLOW": 3, "REPORT_RESTORE_RISK": 4,
            "DISABLE_DATA_FLOW": 5, "BLOCK_RESTORE": 6, "DELETE_RECORD": 7,
            "REDACT_RECORD": 8, "ANONYMIZE_RECORD": 9,
            "VERIFY_RECORD_ABSENT": 10, "VERIFY_RECORD_PRESENT": 11,
            "VERIFY_RECORD_REDACTED": 12, "VERIFY_RECORD_ANONYMIZED": 13,
            "VERIFY_DATA_FLOW_DISABLED": 14, "VERIFY_RESTORE_BLOCKED": 15
        }

        self.steps_json.sort(key=lambda x: (
            phase_order.get(x.phase.value, 99),
            op_order.get(x.operation, 99),
            x.system_id,
            x.resource_id
        ))

        for i, step in enumerate(self.steps_json, 1):
            step.step_no = i