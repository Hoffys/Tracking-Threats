# Railway PostgreSQL Scan Repository Setup

## Target architecture

```text
Browser or web client
        |
        v
Tracking-Threats web/API service
        |
        | private DATABASE_URL
        v
PostgreSQL scan repository service
```

PostgreSQL has no public application route. Only the backend receives its
connection URL. The application creates the repository tables during startup.

## Railway steps

1. Open the existing Railway project and production environment.
2. Select **Add**, choose **Database**, and choose **PostgreSQL**.
3. Wait until the PostgreSQL service is active.
4. Open the **Tracking-Threats** service, then open **Variables**.
5. Add a variable reference named `DATABASE_URL` whose value is
   `${{Postgres.DATABASE_URL}}`. If the service was renamed, select that service's
   `DATABASE_URL` from Railway's variable-reference menu instead of typing a
   password manually.
6. Add `DATABASE_SSL=false` and `DATABASE_POOL_SIZE=10` to Tracking-Threats.
7. Keep `STORE_SCAN_CONTENT=false`, `SCAN_RETENTION_DAYS=30`, and
   `AUDIT_RETENTION_DAYS=90`.
8. Deploy the pending changes.
9. Open `/api/health` and confirm the response includes
   `"repository":"postgresql"`.
10. Submit one acknowledged test scan and confirm it appears in History.
11. Restart or redeploy the web service and confirm the test record remains.

## Existing SQLite records

The new PostgreSQL repository starts empty. Before switching, either delete old
scan history through the application or retain the old Railway volume only for
a short, documented rollback period. This release does not automatically copy
SQLite records because silent duplication would conflict with deletion and
retention expectations.

After PostgreSQL is verified and the rollback period ends, detach and delete the
old SQLite volume so stale personal data is not retained indefinitely.

## Rollback

Remove `DATABASE_URL`, restore `DATABASE_PATH=/data/threattrack.sqlite`, and
redeploy. The backend will use SQLite again. Never place a database URL or
password in GitHub, screenshots, source files, or frontend variables.
