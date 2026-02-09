# IPTV AU for Docker / Channels

https://www.matthuisman.nz/....

## 9Now Login and Token Refresh

This project now includes local 9Now device login and token refresh logic (ported from `slyguy.9now`) directly in `app.py`.

### Web UI Login Flow

1. Open `http://<host>/9now`
2. Click **Start Device Login**
3. Open `https://9now.com.au/activate` and enter the shown code
4. The page will poll automatically until login succeeds
5. Confirm status shows **Logged in**

### Auto Refresh

- Token auto-refresh is enabled by default.
- Default refresh interval is **60 minutes**.
- You can change both settings in the `/9now` page.
- You can also trigger manual refresh from the same page.

### 9Now Endpoints

- `GET /9now` UI for login + refresh controls
- `GET /9now_auth` current auth status JSON
- `GET /9now_login` start device login
- `GET /9now_login_poll?auth_code=...&device_code=...` poll device login
- `GET /9now_refresh?force=1` force token refresh now
- `GET /9now_auto_refresh?enabled=1&interval_minutes=60` update auto-refresh settings
- `GET /9now_logout` clear local 9Now tokens

### Container Health and Shutdown

- `GET /healthz` returns a liveness payload used by container health checks.
- The Docker image now includes a `HEALTHCHECK` against `http://127.0.0.1/healthz`.
- The app handles `SIGTERM`/`SIGINT` for graceful shutdown:
  - stops accepting requests
  - closes the HTTP server cleanly
  - stops the background 9Now auto-refresh worker

### Keep 9Now Login Across Container Restart/Recreate

- 9Now auth tokens are stored in `9now_auth.json` under `APP_DATA_DIR`.
- In Docker, default `APP_DATA_DIR` is `/data/iptv-au-docker`.
- To persist login across container recreate/update, mount a persistent volume to `/data`.
- The included `docker-compose.yml` now mounts a named volume (`iptv-au-data`) for this.

### Environment Variables

- `NINENOW_AUTO_REFRESH_ENABLED` default: `1` (`0` to disable)
- `NINENOW_AUTO_REFRESH_INTERVAL_MINUTES` default: `60`
- `LOG_LEVEL` default: `INFO`
  - Common values: `DEBUG`, `INFO`, `WARNING`, `ERROR`
  - Use `DEBUG` to see detailed 9Now login/refresh lifecycle logs
- `APP_DATA_DIR` default: `/data/iptv-au-docker` in Docker, otherwise temp directory
- `NINENOW_AUTH_STATE_PATH` optional full path override for token state file
- `REGION` default: `all`
