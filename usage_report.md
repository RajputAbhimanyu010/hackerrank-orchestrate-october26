# API Usage & Efficiency Report

## Configuration
* **Model Used:** `gpt-4o-mini` (Cost-effective parsing)
* **Response Format:** `json_object`

## Efficiency Summary
* Pipeline heavily reduced LLM calls by leveraging deterministic temporal reduction on structured `system_activity.csv` logs first.
* External API was isolated purely to unstructured evidence files matching active target IDs, minimizing token bloat.
