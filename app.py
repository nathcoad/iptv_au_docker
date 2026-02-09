#!/usr/bin/python3
import os
import json
import gzip
import time
import threading
import signal
import logging
import argparse
from base64 import b64encode
from io import BytesIO
from tempfile import gettempdir
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from base64 import b64decode
from urllib.parse import urlparse, parse_qsl, urlencode, unquote, parse_qs

import requests
from cachelib import SimpleCache


PLAYLIST_PATH = 'playlist.m3u8'
EPG_PATH = 'epg.xml'
CLEAR_CACHE_PATH = 'clear_cache'
DEEPLINK_PATH = 'deep_link'
STATUS_PATH = ''
HEALTH_PATH = 'healthz'
NINENOW_UI_PATH = '9now'
NINENOW_AUTH_STATUS_PATH = '9now_auth'
NINENOW_LOGIN_PATH = '9now_login'
NINENOW_LOGIN_POLL_PATH = '9now_login_poll'
NINENOW_LOGOUT_PATH = '9now_logout'
NINENOW_REFRESH_PATH = '9now_refresh'
NINENOW_AUTO_REFRESH_PATH = '9now_auto_refresh'
APP_URL = 'https://i.mjh.nz/au/{region}/tv.json.gz'
EPG_URL = 'https://i.mjh.nz/au/{region}/epg.xml.gz'
DELIMITER = '|'
TIMEOUT = (5,20) #connect,read
CACHE_TIME = os.getenv("CACHE_TIME", 300) # default of 5mins
CHUNKSIZE = 1024
REGION = os.environ.get('REGION', 'all')
NINENOW_AUTH_URL = 'https://login.nine.com.au/api/device{}'
NINENOW_LIVESTREAM_URL = 'https://api.9now.com.au/ctv/livestreams'
NINENOW_ACTIVATE_URL = 'https://9now.com.au/activate'
NINENOW_CLIENT_ID = '9nowdevice'
NINENOW_DEFAULT_AUTO_REFRESH_ENABLED = os.getenv('NINENOW_AUTO_REFRESH_ENABLED', '1').strip().lower() not in ('0', 'false', 'no', 'off')
NINENOW_DEFAULT_AUTO_REFRESH_INTERVAL_MINUTES = max(1, int(os.getenv('NINENOW_AUTO_REFRESH_INTERVAL_MINUTES', '60')))
NINENOW_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
}
LOG_LEVEL_NAME = os.getenv('LOG_LEVEL', 'INFO').strip().upper()
LOG_LEVEL = getattr(logging, LOG_LEVEL_NAME, logging.INFO)
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s %(levelname)s [%(threadName)s] %(message)s',
)
logger = logging.getLogger('iptv_au')
APP_STARTED_AT = int(time.time())

CACHE_DIR = os.path.join(gettempdir(), 'iptv-au-docker')
os.makedirs(CACHE_DIR, exist_ok=True)
logger.info('Cache dir: %s', CACHE_DIR)
cache = SimpleCache()
NINENOW_AUTH_STATE_PATH = os.path.join(CACHE_DIR, '9now_auth.json')


def is_valid_url(url):
    if not url:
        return False

    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def _mask_value(value):
    if not value:
        return ''

    text = str(value)
    if len(text) <= 4:
        return '*' * len(text)
    return '{}...{}'.format(text[:2], text[-2:])


class NineNowAuth(object):
    def __init__(self, state_path):
        self._state_path = state_path
        self._lock = threading.RLock()
        self._state = self._load_state()
        self._stop_event = threading.Event()
        self._next_auto_refresh_at = 0

        with self._lock:
            if 'auto_refresh_enabled' not in self._state:
                self._state['auto_refresh_enabled'] = NINENOW_DEFAULT_AUTO_REFRESH_ENABLED

            if 'auto_refresh_interval_minutes' not in self._state:
                self._state['auto_refresh_interval_minutes'] = NINENOW_DEFAULT_AUTO_REFRESH_INTERVAL_MINUTES

            self._next_auto_refresh_at = time.time() + self._safe_interval_minutes_locked() * 60
            self._save_state_locked()

        self._worker = threading.Thread(target=self._auto_refresh_worker, name='9now-auto-refresh', daemon=True)
        self._worker.start()
        logger.info(
            '9Now auth manager initialized (logged_in=%s, auto_refresh_enabled=%s, interval_minutes=%s)',
            bool(self._state.get('access_token')),
            bool(self._state.get('auto_refresh_enabled', NINENOW_DEFAULT_AUTO_REFRESH_ENABLED)),
            self._state.get('auto_refresh_interval_minutes', NINENOW_DEFAULT_AUTO_REFRESH_INTERVAL_MINUTES),
        )

    @property
    def worker_alive(self):
        return self._worker.is_alive()

    def stop(self, timeout=10):
        logger.info('Stopping 9Now auth background worker')
        self._stop_event.set()
        if self._worker.is_alive():
            self._worker.join(timeout=timeout)

        if self._worker.is_alive():
            logger.warning('9Now auth worker did not stop within %ss', timeout)
        else:
            logger.info('9Now auth background worker stopped')

    @property
    def logged_in(self):
        with self._lock:
            return bool(self._state.get('access_token'))

    @staticmethod
    def parse_bool(value):
        if value is None:
            return None

        text = str(value).strip().lower()
        if text in ('1', 'true', 'yes', 'on'):
            return True
        if text in ('0', 'false', 'no', 'off'):
            return False
        raise Exception('Invalid boolean value: {}'.format(value))

    def _safe_interval_minutes_locked(self):
        try:
            value = int(self._state.get('auto_refresh_interval_minutes', NINENOW_DEFAULT_AUTO_REFRESH_INTERVAL_MINUTES))
        except (TypeError, ValueError):
            value = NINENOW_DEFAULT_AUTO_REFRESH_INTERVAL_MINUTES
        return max(1, value)

    def _schedule_next_auto_refresh_locked(self):
        self._next_auto_refresh_at = time.time() + self._safe_interval_minutes_locked() * 60

    def status(self):
        with self._lock:
            token_expires = int(self._state.get('token_expires', 0))
            logged_in = bool(self._state.get('access_token'))
            auto_refresh_enabled = bool(self._state.get('auto_refresh_enabled', NINENOW_DEFAULT_AUTO_REFRESH_ENABLED))
            auto_refresh_interval_minutes = self._safe_interval_minutes_locked()
            next_auto_refresh_at = int(self._next_auto_refresh_at) if auto_refresh_enabled else 0
            return {
                'logged_in': logged_in,
                'token_expires': token_expires,
                'token_expired': token_expires <= int(time.time()) if logged_in else True,
                'has_refresh_token': bool(self._state.get('refresh_token')),
                'auto_refresh_enabled': auto_refresh_enabled,
                'auto_refresh_interval_minutes': auto_refresh_interval_minutes,
                'next_auto_refresh_at': next_auto_refresh_at,
            }

    def _load_state(self):
        if not os.path.exists(self._state_path):
            logger.info('9Now auth state file does not exist yet: %s', self._state_path)
            return {}

        try:
            with open(self._state_path, 'r', encoding='utf8') as f:
                data = json.load(f)
            logger.info('Loaded 9Now auth state from %s', self._state_path)
            return data if isinstance(data, dict) else {}
        except Exception:
            logger.exception('Failed to read 9Now auth state from %s', self._state_path)
            return {}

    def _save_state_locked(self):
        tmp_path = '{}.tmp'.format(self._state_path)
        with open(tmp_path, 'w', encoding='utf8') as f:
            json.dump(self._state, f)
        os.replace(tmp_path, self._state_path)
        logger.debug('Saved 9Now auth state to %s', self._state_path)

    def _clear_tokens_locked(self):
        for key in ('access_token', 'refresh_token', 'token_expires'):
            self._state.pop(key, None)
        self._save_state_locked()
        logger.info('Cleared stored 9Now tokens')

    @staticmethod
    def _response_json(response):
        try:
            return response.json()
        except ValueError:
            snippet = response.text[:200] if response.text else ''
            raise Exception('Invalid 9Now response ({}): {}'.format(response.status_code, snippet))

    def _update_tokens_locked(self, data):
        self._state['access_token'] = data['accessToken']
        self._state['token_expires'] = int(time.time()) + int(data['expiresIn']) - 30
        if data.get('refresh_token'):
            self._state['refresh_token'] = data['refresh_token']
        self._schedule_next_auto_refresh_locked()
        self._save_state_locked()
        logger.info(
            'Stored new 9Now token state (expires_at=%s, has_refresh_token=%s)',
            self._state['token_expires'],
            bool(self._state.get('refresh_token')),
        )

    def logout(self):
        logger.info('Logging out from 9Now (local token clear)')
        with self._lock:
            self._clear_tokens_locked()
            self._schedule_next_auto_refresh_locked()

    def configure_auto_refresh(self, enabled=None, interval_minutes=None):
        with self._lock:
            if enabled is not None:
                self._state['auto_refresh_enabled'] = bool(enabled)

            if interval_minutes is not None:
                try:
                    parsed = int(interval_minutes)
                except (TypeError, ValueError):
                    raise Exception('interval_minutes must be a positive integer')

                if parsed < 1:
                    raise Exception('interval_minutes must be at least 1')
                self._state['auto_refresh_interval_minutes'] = parsed

            self._schedule_next_auto_refresh_locked()
            self._save_state_locked()
            logger.info(
                'Updated 9Now auto-refresh settings (enabled=%s, interval_minutes=%s, next_refresh_at=%s)',
                bool(self._state.get('auto_refresh_enabled', NINENOW_DEFAULT_AUTO_REFRESH_ENABLED)),
                self._safe_interval_minutes_locked(),
                int(self._next_auto_refresh_at),
            )

    def device_code(self):
        logger.info('Starting 9Now device-code login flow')
        self.logout()
        params = {'client_id': NINENOW_CLIENT_ID}
        response = requests.post(NINENOW_AUTH_URL.format('/code'), params=params, data={}, headers=NINENOW_HEADERS, timeout=TIMEOUT)
        data = self._response_json(response)
        if response.status_code >= 400:
            error = data.get('error', 'unknown error')
            logger.error('9Now device-code start failed (status=%s, error=%s)', response.status_code, error)
            raise Exception('Failed to start 9Now device login: {}'.format(error))

        logger.info('9Now device-code login started (expires_in=%s, interval=%s)', data.get('expires_in'), data.get('interval'))
        return data

    def device_login(self, auth_code, device_code):
        logger.info(
            'Polling 9Now device login token endpoint (auth_code=%s, device_code=%s)',
            _mask_value(auth_code),
            _mask_value(device_code),
        )
        params = {
            'auth_code': auth_code,
            'device_code': device_code,
            'client_id': NINENOW_CLIENT_ID,
            'response_types': 'id_token',
        }
        response = requests.get(NINENOW_AUTH_URL.format('/token'), params=params, headers=NINENOW_HEADERS, timeout=TIMEOUT)
        data = self._response_json(response)
        if 'accessToken' not in data:
            logger.info(
                '9Now device login pending or failed (status=%s, error=%s)',
                response.status_code,
                self._extract_error(data) or 'authorization_pending',
            )
            return False, data

        with self._lock:
            self._update_tokens_locked(data)
        logger.info('9Now device login completed successfully')
        return True, data

    def refresh_token(self, force=False):
        with self._lock:
            access_token = self._state.get('access_token')
            token_expires = int(self._state.get('token_expires', 0))
            refresh_token = self._state.get('refresh_token')

        if not access_token:
            logger.debug('Skipping 9Now token refresh because no access token is stored')
            return False

        if not force and token_expires > time.time():
            logger.debug('Skipping 9Now token refresh because token has not expired yet (expires_at=%s)', token_expires)
            return False

        if not refresh_token:
            logger.error('9Now refresh requested but refresh token is missing')
            raise Exception('9Now refresh token is missing. Login again via /{}.'.format(NINENOW_LOGIN_PATH))

        logger.info('Refreshing 9Now token (force=%s)', force)
        params = {
            'refresh_token': refresh_token,
            'client_id': NINENOW_CLIENT_ID,
            'response_types': 'id_token',
        }
        response = requests.post(NINENOW_AUTH_URL.format('/refresh-token'), params=params, headers=NINENOW_HEADERS, timeout=TIMEOUT)
        data = self._response_json(response)
        if 'error' in data:
            logger.error('9Now token refresh failed (status=%s, error=%s)', response.status_code, data.get('error'))
            self.logout()
            raise Exception('Failed to refresh 9Now token: {}. Login again via /{}.'.format(data['error'], NINENOW_LOGIN_PATH))

        if 'accessToken' not in data:
            logger.error('9Now refresh response missing accessToken (status=%s)', response.status_code)
            raise Exception('9Now refresh response did not include accessToken')

        with self._lock:
            self._update_tokens_locked(data)
        logger.info('9Now token refresh succeeded')
        return True

    def get_access_token(self):
        with self._lock:
            token = self._state.get('access_token')

        if not token:
            logger.warning('No 9Now access token available; login required')
            raise Exception(
                '9Now login required. Start device login via /{}, then complete polling via /{}.'
                .format(NINENOW_LOGIN_PATH, NINENOW_LOGIN_POLL_PATH)
            )

        self.refresh_token()

        with self._lock:
            token = self._state.get('access_token')

        if not token:
            raise Exception('9Now login required. Start device login via /{}.'.format(NINENOW_LOGIN_PATH))

        return token

    @staticmethod
    def _extract_error(data):
        if not isinstance(data, dict):
            return None

        if 'error' in data:
            return data['error']

        errors = data.get('errors')
        if isinstance(errors, list) and errors:
            first = errors[0]
            if isinstance(first, dict):
                return first.get('message')
            return str(first)

        return None

    def channels(self, region):
        logger.info('Requesting 9Now channel data for region=%s', region)
        access_token = self.get_access_token()
        params = {
            'device': 'web',
            'streamParams': 'web,chrome,windows',
            'region': region,
            'offset': 0,
        }
        headers = dict(NINENOW_HEADERS)
        headers['Authorization'] = 'Bearer {}'.format(access_token)
        response = requests.get(NINENOW_LIVESTREAM_URL, params=params, headers=headers, timeout=TIMEOUT)

        if response.status_code == 401:
            logger.warning('Received 401 from 9Now livestream API; forcing token refresh and retry')
            self.refresh_token(force=True)
            refreshed_token = self.get_access_token()
            headers['Authorization'] = 'Bearer {}'.format(refreshed_token)
            response = requests.get(NINENOW_LIVESTREAM_URL, params=params, headers=headers, timeout=TIMEOUT)

        data = self._response_json(response)
        if response.status_code >= 400:
            error = self._extract_error(data) or 'HTTP {}'.format(response.status_code)
            logger.error('9Now livestream request failed (status=%s, error=%s)', response.status_code, error)
            raise Exception('9Now livestream request failed: {}'.format(error))

        error = self._extract_error(data)
        if error:
            logger.error('9Now API returned error payload: %s', error)
            raise Exception('9Now API error: {}'.format(error))

        livestream = data.get('data', {}).get('getLivestream')
        if not livestream:
            logger.error('9Now livestream response missing expected data.getLivestream payload')
            raise Exception('Unexpected 9Now livestream response')

        logger.info('9Now channel payload retrieved successfully for region=%s', region)
        return livestream

    def _auto_refresh_worker(self):
        while not self._stop_event.wait(5):
            with self._lock:
                auto_refresh_enabled = bool(self._state.get('auto_refresh_enabled', NINENOW_DEFAULT_AUTO_REFRESH_ENABLED))
                if not auto_refresh_enabled:
                    continue

                next_refresh_at = self._next_auto_refresh_at

            if time.time() < next_refresh_at:
                continue

            try:
                logger.info('9Now auto-refresh trigger fired')
                refreshed = self.refresh_token(force=True)
                if refreshed:
                    logger.info('9Now token auto-refresh completed')
                else:
                    logger.info('9Now auto-refresh did not refresh token (not logged in or not required)')
            except Exception as exc:
                logger.exception('9Now token auto-refresh failed: %s', exc)

            with self._lock:
                self._schedule_next_auto_refresh_locked()
                logger.debug('Scheduled next 9Now auto-refresh at %s', int(self._next_auto_refresh_at))


ninenow_auth = NineNowAuth(NINENOW_AUTH_STATE_PATH)


class Handler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self._params = {}
        super().__init__(*args, **kwargs)

    def _error(self, message):
        logger.error('Request handling error for path=%s: %s', self.path, message)
        self.send_response(500)
        self.end_headers()
        self.wfile.write(f'Error: {message}'.encode('utf8'))

    def _json_response(self, payload, status=200):
        self.send_response(status)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode('utf8'))

    @staticmethod
    def _format_timestamp(timestamp):
        if not timestamp:
            return 'N/A'

        try:
            return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(timestamp)))
        except Exception:
            return 'N/A'

    def do_GET(self):
        # Serve the favicon.ico file
        if self.path == '/favicon.ico':
            self._serve_favicon()
            return

        routes = {
            PLAYLIST_PATH: self._playlist,
            EPG_PATH: self._epg,
            STATUS_PATH: self._status,
            HEALTH_PATH: self._health,
            CLEAR_CACHE_PATH: self._clear_cache,
            NINENOW_UI_PATH: self._9now_ui,
            DEEPLINK_PATH: self._deeplink,
            NINENOW_AUTH_STATUS_PATH: self._9now_auth_status,
            NINENOW_LOGIN_PATH: self._9now_login,
            NINENOW_LOGIN_POLL_PATH: self._9now_login_poll,
            NINENOW_LOGOUT_PATH: self._9now_logout,
            NINENOW_REFRESH_PATH: self._9now_refresh,
            NINENOW_AUTO_REFRESH_PATH: self._9now_auto_refresh,
        }

        parsed = urlparse(self.path)
        func = parsed.path.split('/')[1]
        self._params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        logger.debug('Incoming GET request path=%s route=%s params=%s', self.path, func, self._params)

        if func not in routes:
            logger.warning('Unknown route requested: %s', self.path)
            self.send_response(404)
            self.end_headers()
            return

        try:
            routes[func]()
        except Exception as e:
            logger.exception('Route execution failed for %s', self.path)
            self._error(e)

    def _health(self):
        auth_status = ninenow_auth.status()
        cache_dir_exists = os.path.isdir(CACHE_DIR)
        auth_worker_alive = ninenow_auth.worker_alive
        healthy = cache_dir_exists and auth_worker_alive

        payload = {
            'status': 'ok' if healthy else 'degraded',
            'timestamp': int(time.time()),
            'uptime_seconds': int(time.time()) - APP_STARTED_AT,
            'cache_dir': CACHE_DIR,
            'cache_dir_exists': cache_dir_exists,
            'auth_worker_alive': auth_worker_alive,
            'logged_in': auth_status['logged_in'],
            'region': REGION,
        }
        self._json_response(payload, status=200 if healthy else 503)

    def _deeplink(self):
        plugin_url = '/'.join(self.path.split('/')[2:])
        parsed = urlparse(plugin_url)
        params = dict(parse_qsl(parsed.query))
        logger.info('9Now deeplink request received (region=%s, reference=%s)', params.get('region'), params.get('reference'))

        if 'region' not in params or 'reference' not in params:
            raise Exception('Invalid 9Now deeplink parameters')

        data = ninenow_auth.channels(params['region'])
        data['channels'].extend([row for row in data['events'] if row['type'] == 'live-event' and row['nextEvent']['name']])

        url = None
        for row in data['channels']:
            if row['referenceId'] == params['reference']:
                url = row['stream']['url']
                break

        if not url:
            raise Exception("couldnt find stream url")

        try:
            _url = url
            parsed_url = urlparse(_url)
            query_params = parse_qs(parsed_url.query)

            yo_fb_encoded = query_params.get('yo.eb.fb', [None])[0]
            if yo_fb_encoded:
                yo_fb_decoded_once = unquote(yo_fb_encoded)
                _url = b64decode(yo_fb_decoded_once).decode('utf-8')
            else:
                _url = None

            if not is_valid_url(_url):
                yo_pp_encoded = query_params.get('yo.pp', [None])[0]
                if yo_pp_encoded:
                    yo_pp_decoded_once = unquote(yo_pp_encoded)
                    yo_pp_base64_decoded = b64decode(yo_pp_decoded_once).decode('utf-8')
                else:
                    yo_pp_base64_decoded = ''
                yo_up_encoded = query_params.get('yo.up', [None])[0]
                yo_up_decoded = unquote(yo_up_encoded)
                _url = yo_up_decoded + 'index.m3u8?' + yo_pp_base64_decoded

            if not is_valid_url(_url):
                raise Exception(f"Invalid url: {_url}")

            url = _url
        except Exception as e:
            logger.warning('Failed to decode raw stream url, using fallback (url=%s, error=%s)', url, e)
            # fix encoded query
            if '?' in url:
                url = url.split('?')[0] + '?' + urlencode(parse_qsl(url.split('?')[1]))

        url = url.strip('?')
        logger.info('Redirecting 9Now deeplink to stream url: %s', url)
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def _9now_ui(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

        auth_status = ninenow_auth.status()
        login_text = 'Logged in' if auth_status['logged_in'] else 'Not logged in'
        token_expiry = self._format_timestamp(auth_status.get('token_expires'))
        next_refresh = self._format_timestamp(auth_status.get('next_auto_refresh_at'))
        auto_checked = 'checked' if auth_status.get('auto_refresh_enabled') else ''
        auto_interval = int(auth_status.get('auto_refresh_interval_minutes', NINENOW_DEFAULT_AUTO_REFRESH_INTERVAL_MINUTES))

        html = '''
<!doctype html>
<html>
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>9Now Login</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            margin: 0;
            padding: 24px;
            background: #f6f8fb;
            color: #132036;
        }}
        .card {{
            max-width: 840px;
            margin: 0 auto;
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 8px 24px rgba(9, 30, 66, 0.08);
            padding: 20px;
        }}
        h1, h2 {{
            margin: 0 0 10px 0;
        }}
        h2 {{
            margin-top: 22px;
            font-size: 18px;
        }}
        p {{
            margin: 8px 0;
        }}
        .actions {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 12px;
        }}
        button {{
            border: 0;
            border-radius: 8px;
            background: #0058cc;
            color: #fff;
            padding: 10px 14px;
            cursor: pointer;
            font-weight: 600;
        }}
        button.secondary {{
            background: #4d596a;
        }}
        code {{
            background: #edf1f7;
            border-radius: 6px;
            padding: 2px 6px;
        }}
        .row {{
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
            margin-top: 10px;
        }}
        .row input[type="number"] {{
            width: 96px;
            padding: 6px;
        }}
        #message {{
            margin-top: 12px;
            padding: 10px;
            border-radius: 8px;
            background: #edf1f7;
        }}
        #login-details {{
            margin-top: 14px;
            padding: 12px;
            border-radius: 8px;
            background: #f5f9ff;
            display: none;
        }}
        a {{
            color: #0058cc;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>9Now Authentication</h1>
        <p>Status: <strong id="login-status">{login_text}</strong></p>
        <p>Token expires: <strong id="token-expiry">{token_expiry}</strong></p>
        <p>Next auto refresh: <strong id="next-refresh">{next_refresh}</strong></p>

        <div class="actions">
            <button onclick="startLogin()">Start Device Login</button>
            <button class="secondary" onclick="pollLogin(true)">Poll Login Now</button>
            <button class="secondary" onclick="refreshNow()">Refresh Token Now</button>
            <button class="secondary" onclick="logoutNow()">Logout</button>
        </div>

        <div id="login-details">
            <p>1. Open <a href="{activate_url}" target="_blank" rel="noopener noreferrer">{activate_url}</a></p>
            <p>2. Enter code: <code id="auth-code"></code></p>
            <p>3. Polling every <span id="poll-interval">0</span> seconds until complete.</p>
        </div>

        <h2>Auto Refresh</h2>
        <div class="row">
            <label>
                <input type="checkbox" id="auto-enabled" {auto_checked} />
                Enable automatic refresh
            </label>
        </div>
        <div class="row">
            <label>
                Interval (minutes):
                <input type="number" id="auto-interval" min="1" value="{auto_interval}" />
            </label>
            <button class="secondary" onclick="saveAutoRefresh()">Save Settings</button>
        </div>

        <p id="message">Ready.</p>
    </div>

    <script>
        let pollTimer = null;
        let currentAuthCode = '';
        let currentDeviceCode = '';

        function setMessage(message) {{
            document.getElementById('message').innerText = message;
        }}

        function formatTimestamp(ts) {{
            if (!ts) {{
                return 'N/A';
            }}

            const date = new Date(ts * 1000);
            if (Number.isNaN(date.getTime())) {{
                return 'N/A';
            }}

            return date.toLocaleString();
        }}

        async function refreshStatus() {{
            const response = await fetch('/{auth_path}');
            const data = await response.json();
            document.getElementById('login-status').innerText = data.logged_in ? 'Logged in' : 'Not logged in';
            document.getElementById('token-expiry').innerText = formatTimestamp(data.token_expires);
            document.getElementById('next-refresh').innerText = formatTimestamp(data.next_auto_refresh_at);
            document.getElementById('auto-enabled').checked = !!data.auto_refresh_enabled;
            document.getElementById('auto-interval').value = data.auto_refresh_interval_minutes;
        }}

        async function startLogin() {{
            const response = await fetch('/{login_path}');
            const data = await response.json();

            currentAuthCode = data.auth_code || '';
            currentDeviceCode = data.device_code || '';
            const interval = Number(data.interval || 5);

            document.getElementById('auth-code').innerText = currentAuthCode || 'N/A';
            document.getElementById('poll-interval').innerText = interval;
            document.getElementById('login-details').style.display = 'block';

            if (pollTimer) {{
                clearInterval(pollTimer);
            }}

            pollTimer = setInterval(function() {{
                pollLogin(false);
            }}, Math.max(1, interval) * 1000);

            setMessage('Device login started. Complete activation in browser.');
        }}

        async function pollLogin(showPendingMessage) {{
            if (!currentAuthCode || !currentDeviceCode) {{
                setMessage('Start device login first.');
                return;
            }}

            const url = '/{poll_path}?auth_code=' + encodeURIComponent(currentAuthCode) + '&device_code=' + encodeURIComponent(currentDeviceCode);
            const response = await fetch(url);
            const data = await response.json();

            if (data.success) {{
                if (pollTimer) {{
                    clearInterval(pollTimer);
                    pollTimer = null;
                }}
                await refreshStatus();
                setMessage('Login complete.');
                return;
            }}

            if (data.error && data.error !== 'authorization_pending') {{
                setMessage('Login error: ' + data.error);
                return;
            }}

            if (showPendingMessage) {{
                setMessage('Waiting for activation...');
            }}
        }}

        async function refreshNow() {{
            const response = await fetch('/{refresh_path}?force=1');
            const data = await response.json();
            await refreshStatus();

            if (!data.success) {{
                setMessage('Manual refresh skipped: ' + (data.error || 'unknown'));
                return;
            }}

            setMessage(data.refreshed ? 'Token refreshed successfully.' : 'Token refresh not required.');
        }}

        async function logoutNow() {{
            await fetch('/{logout_path}');
            if (pollTimer) {{
                clearInterval(pollTimer);
                pollTimer = null;
            }}
            currentAuthCode = '';
            currentDeviceCode = '';
            document.getElementById('login-details').style.display = 'none';
            await refreshStatus();
            setMessage('Logged out.');
        }}

        async function saveAutoRefresh() {{
            const enabled = document.getElementById('auto-enabled').checked ? '1' : '0';
            const interval = document.getElementById('auto-interval').value || '60';
            const response = await fetch('/{auto_path}?enabled=' + enabled + '&interval_minutes=' + encodeURIComponent(interval));
            const data = await response.json();
            await refreshStatus();
            if (data.success) {{
                setMessage('Auto-refresh settings saved.');
            }} else {{
                setMessage('Failed to save settings.');
            }}
        }}

        refreshStatus();
        setInterval(refreshStatus, 30000);
    </script>
</body>
</html>
        '''.format(
            login_text=login_text,
            token_expiry=token_expiry,
            next_refresh=next_refresh,
            auto_checked=auto_checked,
            auto_interval=auto_interval,
            activate_url=NINENOW_ACTIVATE_URL,
            auth_path=NINENOW_AUTH_STATUS_PATH,
            login_path=NINENOW_LOGIN_PATH,
            poll_path=NINENOW_LOGIN_POLL_PATH,
            logout_path=NINENOW_LOGOUT_PATH,
            refresh_path=NINENOW_REFRESH_PATH,
            auto_path=NINENOW_AUTO_REFRESH_PATH,
        )
        self.wfile.write(html.encode('utf8'))

    def _9now_auth_status(self):
        status = ninenow_auth.status()
        status['activate_url'] = NINENOW_ACTIVATE_URL
        status['server_time'] = int(time.time())
        self._json_response(status)

    def _9now_login(self):
        logger.info('HTTP request to start 9Now device login')
        data = ninenow_auth.device_code()
        self._json_response({
            'activate_url': NINENOW_ACTIVATE_URL,
            'auth_code': data.get('auth_code'),
            'device_code': data.get('device_code'),
            'expires_in': data.get('expires_in'),
            'interval': data.get('interval'),
            'poll_url': '/{}?auth_code={}&device_code={}'.format(
                NINENOW_LOGIN_POLL_PATH,
                data.get('auth_code', ''),
                data.get('device_code', ''),
            ),
        })

    def _9now_login_poll(self):
        auth_code = self._params.get('auth_code')
        device_code = self._params.get('device_code')
        if not auth_code or not device_code:
            raise Exception('auth_code and device_code are required')

        logger.info(
            'HTTP request to poll 9Now login (auth_code=%s, device_code=%s)',
            _mask_value(auth_code),
            _mask_value(device_code),
        )
        success, data = ninenow_auth.device_login(auth_code, device_code)
        payload = {
            'success': success,
            'logged_in': ninenow_auth.logged_in,
        }
        if success:
            logger.info('9Now login poll succeeded')
            payload.update(ninenow_auth.status())
        else:
            logger.info('9Now login poll pending/failure: %s', ninenow_auth._extract_error(data) or 'authorization_pending')
            payload['error'] = ninenow_auth._extract_error(data) or data.get('message') or 'authorization_pending'

        self._json_response(payload)

    def _9now_logout(self):
        logger.info('HTTP request to logout from 9Now')
        ninenow_auth.logout()
        self._json_response({'success': True, 'logged_in': False})

    def _9now_refresh(self):
        status = ninenow_auth.status()
        if not status['logged_in']:
            logger.warning('Manual 9Now refresh requested while not logged in')
            payload = {'success': False, 'refreshed': False, 'error': 'not_logged_in'}
            payload.update(status)
            self._json_response(payload)
            return

        force = NineNowAuth.parse_bool(self._params.get('force'))
        logger.info('HTTP request for manual 9Now token refresh (force=%s)', True if force is None else force)
        refreshed = ninenow_auth.refresh_token(force=(True if force is None else force))
        payload = {'success': True, 'refreshed': bool(refreshed)}
        payload.update(ninenow_auth.status())
        logger.info('Manual 9Now refresh result: refreshed=%s', bool(refreshed))
        self._json_response(payload)

    def _9now_auto_refresh(self):
        enabled = NineNowAuth.parse_bool(self._params.get('enabled')) if 'enabled' in self._params else None
        interval = self._params.get('interval_minutes')
        interval_minutes = None if interval in (None, '') else interval

        logger.info('HTTP request to update 9Now auto-refresh settings (enabled=%s, interval_minutes=%s)', enabled, interval_minutes)
        if enabled is not None or interval_minutes is not None:
            ninenow_auth.configure_auto_refresh(enabled=enabled, interval_minutes=interval_minutes)

        payload = {'success': True}
        payload.update(ninenow_auth.status())
        self._json_response(payload)

    def _clear_cache(self):
        cache.clear()
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b'Cache cleared')

    def _serve_favicon(self):
        # Serve the favicon file as an ICO file
        try:
            with open('favicon.ico', 'rb') as f:
                self.send_response(200)
                self.send_header('Content-Type', 'image/x-icon')
                self.end_headers()
                self.wfile.write(f.read())
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()

    def _app_data(self):
        app_url = APP_URL.format(region=REGION)
        cache_path = cache.get(app_url)
        if cache_path and os.path.exists(cache_path):
            self.log_message(f"Cache hit: {app_url}")
            with open(cache_path, 'r') as f:
                return json.load(f)

        cache_path = os.path.join(CACHE_DIR, b64encode(app_url.encode()).decode())
        self.log_message(f"Downloading {app_url}...")
        resp = requests.get(app_url, stream=True, timeout=TIMEOUT)
        resp.raise_for_status()
        json_text = gzip.GzipFile(fileobj=BytesIO(resp.content)).read()
        data = json.loads(json_text)
        with open(cache_path, 'w') as f:
            json.dump(data, f)
        cache.set(app_url, cache_path, timeout=CACHE_TIME)
        return data

    def _playlist(self):
        channels = self._app_data()

        start_chno = int(self._params['start_chno']) if 'start_chno' in self._params else None
        sort = self._params.get('sort', 'chno')
        include = [x for x in self._params.get('include', '').split(DELIMITER) if x]
        exclude = [x for x in self._params.get('exclude', '').split(DELIMITER) if x]

        self.send_response(200)
        self.send_header('content-type', 'vnd.apple.mpegurl')
        self.end_headers()

        host = self.headers.get('Host')

        self.wfile.write(b'#EXTM3U\n')
        for key in sorted(channels.keys(), key=lambda x: channels[x].get('chno', 9999999) if sort == 'chno' else channels[x]['name'].strip().lower()):
            channel = channels[key]
            logo = channel['logo']
            name = channel['name']
            url = channel['mjh_master']
            channel_id = f'iptv-au-{key}'

            if url.lower().startswith('plugin://slyguy.9now/'):
                url = f"http://{host}/{DEEPLINK_PATH}/{url}"
            elif not url.lower().startswith('http'):
                continue

            # Skip channels that require a license
            if channel.get('license_url'):
                continue

            # Apply include/exclude filters
            if (include and channel_id not in include) or (exclude and channel_id in exclude):
                continue

            chno = ''
            if start_chno is not None:
                if start_chno > 0:
                    chno = f' tvg-chno="{start_chno}"'
                    start_chno += 1
            elif channel.get('chno') is not None:
                chno = ' tvg-chno="{}"'.format(channel['chno'])

            # Write channel information
            self.wfile.write(f'#EXTINF:-1 channel-id="{channel_id}" tvg-id="{key}" tvg-logo="{logo}"{chno},{name}\n{url}\n'.encode('utf8'))

    def _epg(self):
        url = EPG_URL.format(region=REGION)

        cache_path = cache.get(url)
        if cache_path and os.path.exists(cache_path):
            self.log_message(f"Cache hit: {url}...")
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml')
            self.end_headers()
            with open(cache_path, 'rb') as f:
                chunk = f.read(CHUNKSIZE)
                while chunk:
                    self.wfile.write(chunk)
                    chunk = f.read(CHUNKSIZE)
            return

        self.log_message(f"Downloading {url}...")
        cache_path = os.path.join(CACHE_DIR, b64encode(url.encode()).decode())
        # Download the .gz EPG file
        with open(cache_path, 'wb') as cache_f:
            with requests.get(url, stream=True, timeout=TIMEOUT) as resp:
                resp.raise_for_status()

                self.send_response(200)
                self.send_header('Content-Type', 'application/xml')
                self.end_headers()

                # Decompress the .gz content
                with gzip.GzipFile(fileobj=BytesIO(resp.content)) as gz:
                    chunk = gz.read(CHUNKSIZE)
                    while chunk:
                        cache_f.write(chunk)
                        self.wfile.write(chunk)
                        chunk = gz.read(CHUNKSIZE)
        cache.set(url, cache_path, timeout=CACHE_TIME)

    def _status(self):
        # Generate HTML content with the favicon link
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

        host = self.headers.get('Host')
        auth_status = ninenow_auth.status()
        auth_text = 'Logged in' if auth_status['logged_in'] else 'Not logged in'
        auto_enabled = 'Enabled' if auth_status.get('auto_refresh_enabled') else 'Disabled'
        auto_interval = int(auth_status.get('auto_refresh_interval_minutes', NINENOW_DEFAULT_AUTO_REFRESH_INTERVAL_MINUTES))
        auto_next = self._format_timestamp(auth_status.get('next_auto_refresh_at'))
        self.wfile.write(f'''
            <html>
            <head>
                <title>IPTV AU for Docker</title>
                <link rel="icon" href="/favicon.ico" type="image/x-icon">
            </head>
            <body>
                Playlist URL: <b><a href="http://{host}/{PLAYLIST_PATH}">http://{host}/{PLAYLIST_PATH}</a></b><br>
                EPG URL (Set to refresh once per hour): <b><a href="http://{host}/{EPG_PATH}">http://{host}/{EPG_PATH}</a></b><br><br>
                Healthcheck URL: <b><a href="http://{host}/{HEALTH_PATH}">http://{host}/{HEALTH_PATH}</a></b><br><br>
                9Now Login Status: <b>{auth_text}</b><br>
                9Now Login UI: <a href="http://{host}/{NINENOW_UI_PATH}">http://{host}/{NINENOW_UI_PATH}</a><br>
                9Now Auto Refresh: <b>{auto_enabled}</b> every <b>{auto_interval}</b> minutes (next: <b>{auto_next}</b>)<br>
                9Now Auth Status JSON: <a href="http://{host}/{NINENOW_AUTH_STATUS_PATH}">http://{host}/{NINENOW_AUTH_STATUS_PATH}</a><br>
                Start 9Now Device Login: <a href="http://{host}/{NINENOW_LOGIN_PATH}">http://{host}/{NINENOW_LOGIN_PATH}</a><br>
                Poll 9Now Device Login: <code>http://{host}/{NINENOW_LOGIN_POLL_PATH}?auth_code=...&device_code=...</code><br>
                9Now Manual Refresh: <a href="http://{host}/{NINENOW_REFRESH_PATH}">http://{host}/{NINENOW_REFRESH_PATH}</a><br>
                9Now Logout: <a href="http://{host}/{NINENOW_LOGOUT_PATH}">http://{host}/{NINENOW_LOGOUT_PATH}</a><br>
            </body>
            </html>
        '''.encode('utf8'))


class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    block_on_close = False


def run():
    if os.getenv('IS_DOCKER'):
        PORT = 80
    else:
        parser = argparse.ArgumentParser(description="IPTV AU for Docker")
        parser.add_argument("-port", "--PORT", default=80, help="Port number for server to use (optional)")
        args = parser.parse_args()
        PORT = args.PORT

    logger.info('Starting server on port %s (region=%s, auto_refresh_default_enabled=%s, auto_refresh_default_interval_minutes=%s)',
                PORT, REGION, NINENOW_DEFAULT_AUTO_REFRESH_ENABLED, NINENOW_DEFAULT_AUTO_REFRESH_INTERVAL_MINUTES)
    server = ThreadingSimpleServer(('0.0.0.0', int(PORT)), Handler)
    shutdown_requested = threading.Event()

    def _request_shutdown(reason):
        if shutdown_requested.is_set():
            return

        shutdown_requested.set()
        logger.info('Shutdown requested: %s', reason)
        threading.Thread(target=server.shutdown, name='http-shutdown', daemon=True).start()

    def _handle_signal(signum, _frame):
        try:
            signal_name = signal.Signals(signum).name
        except Exception:
            signal_name = str(signum)

        _request_shutdown('signal {}'.format(signal_name))

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        _request_shutdown('keyboard interrupt')
    finally:
        logger.info('Stopping HTTP server')
        try:
            server.shutdown()
        except Exception:
            logger.exception('Error during HTTP server shutdown')

        server.server_close()
        ninenow_auth.stop()
        logger.info('Shutdown complete')


if __name__ == '__main__':
    run()
