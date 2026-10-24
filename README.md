# Data Privacy Audit Orchestrator

## Overview
This project is a Python-based data privacy audit orchestrator submitted for the HackerRank hackathon. It automates the evaluation of user deletion requests by auditing both structured system activity logs and unstructured evidence files.

## Features
*   **Identity Resolution:** Maps primary user emails to specific system resource IDs dynamically using `LINK_RESOURCE_IDENTITY` events.
*   **State Evaluation:** Tracks the exact state of system records at the designated audit time, identifying active data flows and remaining static records.
*   **Evidence Parsing:** Evaluates unstructured text files for exposed PII.
*   **Automated Reporting:** Generates HackerRank-compatible CSV outputs and markdown evaluation reports.

## Execution Instructions
1. Ensure dependencies are installed: 
   `pip install pandas python-dotenv`
2. Run the main orchestrator to process datasets and generate `output.csv`:
   `python code/main.py`
3. Run the evaluation script to generate the final markdown reports:
   `python code/evaluation/main.py`

## Author
Submitted by Abhimanyu Rajput