/* ============================================================================
   TRANSACTION FRAUD DETECTION — SQL RULE SET
   Ananth Pillai | Independent Project
   Dataset: transactions (1,488 rows, 60 accounts, 90-day window, synthetic)
   Engine tested on: SQLite 3 (portable to MySQL/PostgreSQL with minor syntax edits)
   ============================================================================
   Six independent detection rules, each isolating a distinct fraud typology.
   Every query returns only the ACCOUNT/TRANSACTION IDs an analyst would need
   to open a case — not a raw dump — so results are triage-ready.
   ========================================================================== */


/* ----------------------------------------------------------------------
   RULE 1 — STRUCTURING
   Multiple sub-threshold wire transfers from the same account within a
   24-hour window that cumulatively cross a reporting threshold ($10,000).
   Classic "smurfing" pattern used to dodge CTR/STR filing triggers.
------------------------------------------------------------------------- */
WITH wire_txns AS (
    SELECT AccountID, TransactionID, DateTime, Amount,
           date(DateTime) AS TxnDate
    FROM transactions
    WHERE Channel = 'Wire'
),
daily_totals AS (
    SELECT AccountID, TxnDate,
           COUNT(*)            AS num_txns,
           SUM(Amount)         AS total_amount,
           MAX(Amount)         AS largest_single_txn
    FROM wire_txns
    GROUP BY AccountID, TxnDate
)
SELECT AccountID, TxnDate, num_txns, total_amount, largest_single_txn
FROM daily_totals
WHERE num_txns >= 3
  AND total_amount >= 8000
  AND largest_single_txn < 10000        -- every individual leg stays under the reporting threshold
ORDER BY total_amount DESC;


/* ----------------------------------------------------------------------
   RULE 2 — VELOCITY SPIKE
   More than 6 transactions posted by the same account inside a single
   60-minute window. Indicates card testing, bot activity, or account
   takeover rather than normal customer behaviour.
------------------------------------------------------------------------- */
SELECT AccountID,
       date(DateTime)                         AS TxnDate,
       strftime('%H', DateTime)                AS TxnHour,
       COUNT(*)                                AS txns_in_hour,
       SUM(Amount)                             AS total_amount,
       GROUP_CONCAT(TransactionID)              AS transaction_ids
FROM transactions
GROUP BY AccountID, TxnDate, TxnHour
HAVING COUNT(*) > 6
ORDER BY txns_in_hour DESC;


/* ----------------------------------------------------------------------
   RULE 3 — GEOGRAPHIC IMPOSSIBILITY
   Same account transacting in two different countries within a 24-hour
   window — physically implausible without a compromised card/credentials.
------------------------------------------------------------------------- */
SELECT a.AccountID,
       a.TransactionID  AS txn_1_id, a.Country AS country_1, a.DateTime AS time_1,
       b.TransactionID  AS txn_2_id, b.Country AS country_2, b.DateTime AS time_2,
       ROUND((julianday(b.DateTime) - julianday(a.DateTime)) * 24, 1) AS hours_apart
FROM transactions a
JOIN transactions b
  ON a.AccountID = b.AccountID
 AND a.TransactionID < b.TransactionID
 AND a.Country <> b.Country
 AND (julianday(b.DateTime) - julianday(a.DateTime)) * 24 BETWEEN 0 AND 24
ORDER BY a.AccountID, time_1;


/* ----------------------------------------------------------------------
   RULE 4 — ROUND-AMOUNT CLUSTERING
   Wire transfers in suspiciously "clean" denominations (multiples of
   $1,000) above $1,000 — a known laundering / off-books payment marker,
   since genuine commercial invoices rarely settle on round numbers.
------------------------------------------------------------------------- */
SELECT AccountID, TransactionID, DateTime, Amount, MerchantCategory
FROM transactions
WHERE Channel = 'Wire'
  AND Amount >= 1000
  AND Amount % 1000 = 0
ORDER BY Amount DESC;


/* ----------------------------------------------------------------------
   RULE 5 — DUPLICATE TRANSACTION
   Two POS transactions on the same account, same amount, same merchant
   category, posted within 10 minutes of each other — either a processing
   error or a deliberate double-charge/refund-fraud pattern worth review.
------------------------------------------------------------------------- */
SELECT a.AccountID, a.TransactionID AS txn_1, b.TransactionID AS txn_2,
       a.Amount, a.MerchantCategory,
       a.DateTime AS time_1, b.DateTime AS time_2
FROM transactions a
JOIN transactions b
  ON a.AccountID = b.AccountID
 AND a.TransactionID < b.TransactionID
 AND a.Amount = b.Amount
 AND a.MerchantCategory = b.MerchantCategory
 AND a.Channel = 'POS' AND b.Channel = 'POS'
 AND (julianday(b.DateTime) - julianday(a.DateTime)) * 24 * 60 BETWEEN 0 AND 10
ORDER BY a.DateTime;


/* ----------------------------------------------------------------------
   RULE 6 — OFF-HOURS HIGH-VALUE WITHDRAWAL
   ATM cash withdrawals above $2,000 between 12:00 AM and 5:00 AM —
   outside normal customer activity hours and a common cash-out signature.
------------------------------------------------------------------------- */
SELECT AccountID, TransactionID, DateTime, Amount, Country
FROM transactions
WHERE Channel = 'ATM'
  AND Amount > 2000
  AND CAST(strftime('%H', DateTime) AS INTEGER) BETWEEN 0 AND 4
ORDER BY Amount DESC;


/* ----------------------------------------------------------------------
   SUMMARY — ACCOUNT-LEVEL RISK ROLL-UP
   Consolidates all six rules into one flag count per account so an
   analyst can triage by "how many independent rules did this account
   trip", rather than working rule-by-rule.
------------------------------------------------------------------------- */
WITH structuring AS (
    SELECT AccountID FROM (
        SELECT AccountID, date(DateTime) AS d, COUNT(*) n, SUM(Amount) s, MAX(Amount) m
        FROM transactions WHERE Channel='Wire' GROUP BY AccountID, d
    ) WHERE n>=3 AND s>=8000 AND m<10000
),
velocity AS (
    SELECT AccountID FROM (
        SELECT AccountID, date(DateTime) d, strftime('%H',DateTime) h, COUNT(*) n
        FROM transactions GROUP BY AccountID, d, h
    ) WHERE n>6
),
geo AS (
    SELECT DISTINCT a.AccountID FROM transactions a JOIN transactions b
      ON a.AccountID=b.AccountID AND a.TransactionID<b.TransactionID AND a.Country<>b.Country
     AND (julianday(b.DateTime)-julianday(a.DateTime))*24 BETWEEN 0 AND 24
),
round_amt AS (
    SELECT DISTINCT AccountID FROM transactions
    WHERE Channel='Wire' AND Amount>=1000 AND Amount % 1000 = 0
),
dupes AS (
    SELECT DISTINCT a.AccountID FROM transactions a JOIN transactions b
      ON a.AccountID=b.AccountID AND a.TransactionID<b.TransactionID AND a.Amount=b.Amount
     AND a.MerchantCategory=b.MerchantCategory AND a.Channel='POS' AND b.Channel='POS'
     AND (julianday(b.DateTime)-julianday(a.DateTime))*24*60 BETWEEN 0 AND 10
),
offhours AS (
    SELECT DISTINCT AccountID FROM transactions
    WHERE Channel='ATM' AND Amount>2000 AND CAST(strftime('%H',DateTime) AS INTEGER) BETWEEN 0 AND 4
)
SELECT AccountID,
       (AccountID IN (SELECT AccountID FROM structuring)) AS flag_structuring,
       (AccountID IN (SELECT AccountID FROM velocity))    AS flag_velocity,
       (AccountID IN (SELECT AccountID FROM geo))         AS flag_geo,
       (AccountID IN (SELECT AccountID FROM round_amt))   AS flag_round_amount,
       (AccountID IN (SELECT AccountID FROM dupes))       AS flag_duplicate,
       (AccountID IN (SELECT AccountID FROM offhours))    AS flag_off_hours,
       ( (AccountID IN (SELECT AccountID FROM structuring)) +
         (AccountID IN (SELECT AccountID FROM velocity))    +
         (AccountID IN (SELECT AccountID FROM geo))         +
         (AccountID IN (SELECT AccountID FROM round_amt))   +
         (AccountID IN (SELECT AccountID FROM dupes))       +
         (AccountID IN (SELECT AccountID FROM offhours)) )  AS total_rules_triggered
FROM (SELECT DISTINCT AccountID FROM transactions)
WHERE total_rules_triggered >= 1
ORDER BY total_rules_triggered DESC, AccountID;
