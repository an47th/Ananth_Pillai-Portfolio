# Transaction Monitoring, Investigation & SAR Escalation Workflow

End-to-end fraud-ops case study on a 1,488-transaction synthetic dataset (90-day window, 60 accounts).

## Contents
- `case_study_1_sql_fraud_detection.docx` — six-rule SQL detection engine (structuring, velocity spike, geo-impossibility, round-amount clustering, duplicate transaction, off-hours withdrawal)
- `fraud_detection_queries.sql` — the underlying SQL (SQLite, portable to MySQL/PostgreSQL)
- `case_study_2_excel_dashboard.docx` — Excel risk-scoring dashboard (COUNTIFS/SUMIFS, conditional formatting, native charts)
- `fraud_risk_audit.xlsx` — the underlying 5-sheet workbook
- `case_study_3_investigation_sar.docx` — investigation methodology, customer/transaction profiling, behavioural baseline analysis, disposition framework, and a drafted SAR narrative for the one escalated case that met the SAR bar
- `transactions_dataset.csv` — the raw synthetic dataset
- `tableau_fraud_trend_data.csv` / `.xlsx` — rule-trigger event data (45 rows) ready to connect to Tableau for a Fraud Trend Analysis dashboard (rule-trigger volume by disposition, monthly trend, disposition funnel)

## Tools
SQL (SQLite) · Advanced Excel · Tableau
