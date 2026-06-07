#!/usr/bin/python3
import asyncio
import dataclasses
import hashlib
import hmac
import re
import signal
import sys
import json
import threading
import time
import os
import pathlib
import subprocess
import socket
import configparser
import urllib.parse
import urllib.request
import urllib.error
import datetime as dt
import xml.etree.ElementTree
from functools import lru_cache
from typing import Any, Optional, Mapping, Union, Sequence, Dict, Tuple

assert (_ := sys.version_info) > (3, 9), _

# TODO: if server is started in detached process, log to a file and have a command to tail the logs

HOST = '0.0.0.0'
PORT = 4550
PID = os.getpid()

LOCK = threading.Lock()
SHUTDOWN = threading.Event()

AWS_CONFIG_PATH = pathlib.Path.home() / '.aws/config'


def _shutdown(*_):
    SHUTDOWN.set()


signal.signal(signal.SIGINT, _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


class RX:
    REGION = re.compile(r'(af|ap|ca|cn|eu|il|me|mx|sa|us)-(central|east|north|south|west)-\d')


def error(msg) -> Exception:
    print('Error:', msg, file=sys.stderr)
    sys.exit(1)


def wait(seconds):
    for _ in range(int(seconds * 10)):
        if not SHUTDOWN.is_set():
            time.sleep(0.1)


@dataclasses.dataclass
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def load(self) -> dict:
        if self.body.startswith(b"<"):
            return xml_to_dict(self.body)
        return json.loads(self.body)

    def __str__(self):
        return f"HTTP {self.status}: {self.body.decode()}"


class HttpError(Exception):
    response: Response

    def __init__(self, response):
        self.response = response

    def __str__(self):
        return f"Error: {self.response}"


def xml_to_dict(elem: Union[str, bytes, xml.etree.ElementTree.Element]):
    if isinstance(elem, (str, bytes)):
        elem = xml.etree.ElementTree.fromstring(elem)
    tag = elem.tag.split("}")[-1]
    d = {tag: {} if elem.attrib else None}
    children = list(elem)
    if children:
        dd = {}
        for dc in map(xml_to_dict, children):
            for k, v in dc.items():
                if k in dd:
                    if not isinstance(dd[k], list):
                        dd[k] = [dd[k]]
                    dd[k].append(v)
                else:
                    dd[k] = v
        d = {tag: dd}
    if elem.attrib:
        d[tag].update({f"@{k}": v for k, v in elem.attrib.items()})
    if elem.text and elem.text.strip():
        text = elem.text.strip()
        if children or elem.attrib:
            d[tag]["#text"] = text
        else:
            d[tag] = text
    return d


def request(*, url, headers=None, method=None, query=None, data=None, timeout=None, raise_for_status=True) -> Response:
    headers = headers or {}
    if isinstance(data, str):
        data = data.encode()
    elif not isinstance(data, bytes) and data is not None:
        data = json.dumps(data).encode()
        headers.setdefault('Content-Type', 'application/json')

    method = method or ('POST' if data is not None else 'GET')
    if query:
        url += '?' + urllib.parse.urlencode(query, safe='-_.~')
    req = urllib.request.Request(url=url, method=method.upper(), headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k: v for k, v in resp.getheaders()}
            response = Response(status=resp.getcode(), headers=headers, body=resp.read())
    except urllib.error.HTTPError as e:
        headers = {k: v for k, v in e.headers.items()}
        response = Response(status=e.code, headers=headers, body=e.read())
    if raise_for_status and response.status > 300:
        raise HttpError(response=response)
    return response


async def gather_with_concurrency(n, coroutines):
    semaphore = asyncio.Semaphore(n)

    async def sem_coro(coroutine):
        async with semaphore:
            return await coroutine

    return await asyncio.gather(*(sem_coro(c) for c in coroutines))


def now():
    return dt.datetime.now(tz=dt.timezone.utc)


def lsof(port):
    if isinstance(port, int) or isinstance(port, str) and port.isdigit():
        port = f':{port}'
    if _ := subprocess.run(f'lsof -nPi {port}'.split(), capture_output=True).stdout:
        h, *lines = _.decode().splitlines()
        h = h.lower().split()
        return [
            dict(zip(h, re.split(r'\s+', _, maxsplit=len(h))))
            for _ in lines
        ]
    return None


class Server:
    AWS_CONFIG: Optional[configparser.ConfigParser] = None
    SSO_SESSION: Optional[dict[str, Any]] = None
    AWS_ROLES: Optional[dict[tuple[str, str, str], Any]] = None

    @classmethod
    def load_aws_config(cls):
        if not AWS_CONFIG_PATH.exists():
            raise error(f'File not found {AWS_CONFIG_PATH}')
        c = configparser.ConfigParser()
        c.read(AWS_CONFIG_PATH)

        data = {}
        for name, s in c.items():
            if ' ' in (name := name.strip()):
                g, name = name.split()
                _ = data.setdefault(g, {}).setdefault(name, {})
            else:
                _ = data.setdefault(name, {})
            for k, v in s.items():
                _[k] = v.replace('"', '')
        with LOCK:
            cls.AWS_CONFIG = data
        return cls.AWS_CONFIG

    @classmethod
    def get_sso_config(cls, name=None):
        name = name or os.getenv('AWS_SSO_SESSION')
        config = cls.load_aws_config()

        if not (sessions := config.get('sso-session')):
            raise error(f'No [sso-session <name>] found in {AWS_CONFIG_PATH}')

        if name:
            if not (session := sessions.get(name)):
                raise error(f'Requested sso-session {name!r} not found. Available: {sessions}')
        else:
            name, session = list(sessions.items())[0]
            if len(sessions) > 1:
                print(f'Warning: multiple sso-sessions found, selecting {name!r} {session}')

        return {'name': name, **session}

    @classmethod
    def get_profile_config(cls, name, require=False, resolve=True):
        if c := cls.load_aws_config().get('profile', {}).get(name):
            if resolve and (_ := c.pop('include_profile', None)):
                c = {**cls.get_profile_config(_, require=True), **c}
            return c
        elif require:
            raise error(f'No [profile <name>] found in {AWS_CONFIG_PATH}')
        else:
            return None

    @classmethod
    def portal(cls, path, token, region, **query):
        while not SHUTDOWN.is_set():
            url = 'https://portal.sso.{}.amazonaws.com'.format(region) + path
            if query:
                url += '?' + urllib.parse.urlencode(query, safe='-_.~')
            print(url)
            try:
                return request(
                    url=url,
                    headers={'Accept': 'application/json', 'x-amz-sso_bearer_token': token},
                    timeout=30,
                ).load()
            except HttpError as e:
                if e.response.status == 429:
                    wait(0.1)
                    continue
                else:
                    print(e)
                    break
        return False

    @classmethod
    def get_accounts(cls, session=None):
        if not session:
            session = cls.SSO_SESSION
        if _ := cls.portal(
                path='/assignment/accounts',
                token=session['accessToken'],
                region=session['region'],
                max_result=100,
        ):
            assert not _['nextToken'], _
            # there is also emailAddress
            return {a['accountId']: a['accountName'] for a in _['accountList']}
        return None

    @classmethod
    def update_accounts(cls, session):
        if accounts := cls.get_accounts(session=cls.SSO_SESSION):
            with LOCK:
                session['accounts'] = accounts
            return accounts
        return False

    @classmethod
    def refresher(cls) -> None:
        while not SHUTDOWN.is_set():
            cls.get_sso_session()
            wait(seconds=60)

    @classmethod
    def serve(cls):
        cls.get_sso_session(create=True)

        thread = threading.Thread(target=cls.refresher, daemon=True)
        thread.start()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Allow reusing the address after the process exits
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind((HOST, PORT))
                except Exception as e:
                    if 'Address already in use' in str(e):
                        # TODO: force kill the other hanging process if needed?
                        exit()
                    raise
                s.listen()
                s.settimeout(0.5)  # allow responsive shutdown

                print(f"Server listening on {HOST}:{PORT}...")
                while not SHUTDOWN.is_set():
                    try:
                        c, addr = s.accept()
                    except (TimeoutError, socket.timeout):
                        continue
                    except OSError as e:
                        if e.errno == 11:  # EAGAIN on some platforms
                            continue
                        raise
                    with c:
                        if cls.verify_client(addr):
                            print(f"Connected by {addr}")
                        else:
                            print(f"Rejected {addr}")
                            continue

                        def _sendall(x):
                            if isinstance(x, str):
                                x = x.encode()
                            if not isinstance(x, bytes):
                                x = repr(x).encode()
                            c.sendall(x)

                        try:
                            _args = json.loads(c.recv(1024))
                            assert isinstance(_args, list)
                        except Exception as e:
                            print(e)
                            _sendall(e)
                            continue
                        else:
                            print(_args)
                            accounts = cls.get_sso_session(create=True)['accounts']
                            aliases = {v: k for k, v in accounts.items()}
                            account_id = role_name = duration = region = None

                            if _args == ['-l']:
                                account_roles = asyncio.run(cls.get_roles_async(account_ids=accounts))
                                lines = []
                                for account_id, account_name in sorted(accounts.items(), key=lambda x: x[1]):
                                    if roles := account_roles.get(account_id):
                                        lines.append(f'{account_id} {account_name}:')
                                        for _ in roles:
                                            lines.append(f'  - {_}')
                                _sendall('\n'.join(lines))
                                continue

                            for _ in _args:
                                if RX.REGION.match(_):
                                    region = _
                            _args = [_ for _ in _args if not RX.REGION.match(_) and not _ == '--region']

                            chain = {}
                            if len(_args) == 1 and (p := cls.get_profile_config(_args[0])):
                                print(p)
                                while _ := p.get('source_profile'):
                                    if _ in chain:
                                        break
                                    chain[_] = p
                                    p = cls.get_profile_config(_)
                                    print(p)

                                if account_id := p.get('sso_account_id'):
                                    role_name = p['sso_role_name']
                                    region = region or p.get('region')
                                    duration = p.get('duration_seconds')
                                else:
                                    _sendall(f"Invalid profile: {_args[0]} {chain} {p}")
                            else:
                                for a in _args:
                                    if isinstance(a, int):
                                        a = str(a)
                                    if a.isdigit():
                                        if len(a) == 12:
                                            account_id = a
                                        else:
                                            duration = a
                                    elif '-' in a:
                                        if _ := aliases.get(a):
                                            account_id = _
                                        else:
                                            # TODO: profile, chaining
                                            _sendall(f"No access to account {a}, accessible: {aliases}")
                                            break
                                    else:
                                        role_name = a
                            if not account_id:
                                _sendall("Account ID, or name, or profile name are missing")
                                continue
                            role_name = {
                                'admin': 'AdministratorAccess',
                                'read': 'ReadOnlyAccess',
                                None: 'ReadOnlyAccess',
                            }.get(role_name, role_name)

                            roles = cls.get_roles(account_id=account_id)
                            if role_name not in roles:
                                _sendall(f"Invalid role name {role_name}, allowed: {roles}")
                            else:
                                ss = cls.get_role_session(account_id=account_id, role_name=role_name, region=region)
                                while chain:
                                    k, v = chain.popitem()
                                    print("CHAIN:", k)
                                    _ = API.query_api(
                                        action="sts:AssumeRole",
                                        params={"RoleArn": v['role_arn'], "RoleSessionName": k},
                                        region=(region := v.get('region') or region),
                                        access_key=ss['AWS_ACCESS_KEY_ID'],
                                        secret_key=ss['AWS_SECRET_ACCESS_KEY'],
                                        session_token=ss['AWS_SESSION_TOKEN'],
                                    ).load()['AssumeRoleResponse']['AssumeRoleResult']['Credentials']
                                    ss = {
                                        'AWS_ACCESS_KEY_ID': _['AccessKeyId'],
                                        'AWS_SECRET_ACCESS_KEY': _['SecretAccessKey'],
                                        'AWS_SESSION_TOKEN': _['SessionToken'],
                                        'AWS_REGION': region,
                                        'AWS_DEFAULT_REGION': region,
                                        'AWS_ACCOUNT': v['role_arn'].split(':')[4],
                                    }
                                _sendall(json.dumps(ss))
        finally:
            SHUTDOWN.set()
            thread.join()

    @classmethod
    def verify_client(cls, addr):
        client, server = None, None
        if addr[0] != '127.0.0.1':
            return print('Invalid address:', addr)
        if len(procs := lsof(port=f'TCP:{addr[1]}')) != 2:
            return print('Unexpected procs:', procs)
        for p in procs:
            n = p['name'].split('->')
            if len(n) == 2:
                f, t = n
                if f == f'127.0.0.1:{PORT}':
                    server = p
                elif t == f'127.0.0.1:{PORT}':
                    client = p
                else:
                    return print('Invalid process:', p)
        if not client or client['command'] != 'Python':
            return print('Invalid client:', client)
        if not server or server['command'] != 'Python':
            return print('Invalid server:', server)
        if int(server['pid']) != PID:
            # TODO: react on server swap
            # os.system(f'ps -p {p["pid"]} -o lstart=')
            # os.system(f'ps -p {p["pid"]} -o command=')
            # os.system(f'ps -p {p["pid"]} -o comm=')
            return print('Invalid server pid:', server['pid'])
        if client['user'] != server['user']:
            return print('Invalid client user:', client['user'])
        return True

    @classmethod
    def get_roles(cls, account_id, session=None):
        if not session:
            session = cls.get_sso_session(create=True)
        if _ := cls.portal(
                path=f'/assignment/roles',
                token=session['accessToken'],
                region=session['region'],
                account_id=account_id,
                # next_token=...,
                max_result=100,
        ):
            assert not _['nextToken'], _
            roles = []
            for r in _['roleList']:
                assert account_id == r['accountId']
                roles.append(r['roleName'])
            return roles
        return None

    @classmethod
    async def get_roles_async(cls, account_ids, session=None):
        assert isinstance(account_ids, (list, dict))
        if not session:
            session = cls.get_sso_session(create=True)

        async def task(account_id):
            try:
                return account_id, await asyncio.to_thread(cls.get_roles, account_id=account_id,
                                                           session=session)
            except Exception as e:
                print(e)
                raise

        tasks = [task(account_id=_) for _ in account_ids]
        return dict(await gather_with_concurrency(10, tasks))

    @classmethod
    def get_sso_session(cls, create=False):
        print('get_sso_session')

        OIDC_URL = 'https://oidc.{}.amazonaws.com'

        if _ := cls.SSO_SESSION:
            d = now() - dt.datetime.fromisoformat(_['issuedAt'])
            x = dt.timedelta(seconds=_['expiresIn'])
            if d > x:
                print(f'Session expired: {_["issuedAt"]} {_["expiresIn"]}')
                with LOCK:
                    cls.SSO_SESSION = None

            elif d > dt.timedelta(minutes=10):
                url = OIDC_URL.format(_['region']) + '/token'
                tok = request(url=url, data={
                    'grantType': 'refresh_token',
                    'clientId': _['clientId'],
                    'clientSecret': _['clientSecret'],
                    'refreshToken': _['refreshToken'],
                }).load()
                # print('ref', tok)
                with LOCK:
                    cls.SSO_SESSION = {**cls.SSO_SESSION, **tok, 'issuedAt': (_ := now().isoformat())}
                cls.update_accounts(session=cls.SSO_SESSION)
                print('Session refreshed', _)
                return cls.SSO_SESSION
            else:
                print('Session still valid for', int((x - d).total_seconds()), 'seconds')
                if cls.update_accounts(session=cls.SSO_SESSION):
                    return cls.SSO_SESSION
                else:
                    print('Session signed out externally')
                    with LOCK:
                        cls.SSO_SESSION = None
        if not create:
            print('No active sso-session, not creating new one')
            return None

        print('Creating a new session')
        _ = cls.get_sso_config()
        start_url = _['sso_start_url']
        region = _['sso_region']
        scopes: list[str] = _['sso_registration_scopes'].split()
        base = OIDC_URL.format(region)

        reg = request(url=f'{base}/client/register', data={
            'clientName': 'aws.py',
            'clientType': 'public',
            'scopes': scopes,
        }).load()
        client_id = reg['clientId']
        client_secret = reg['clientSecret']

        dev = request(url=f'{base}/device_authorization', data={
            'clientId': client_id,
            'clientSecret': client_secret,
            'startUrl': start_url,
        }).load()

        print('Authorize:', dev['userCode'])
        os.system('open ' + dev['verificationUriComplete'])

        interval = dev['interval']
        expires_at = now() + dt.timedelta(seconds=dev['expiresIn'])

        # Poll /token until authorized or expired
        while now() < expires_at and not SHUTDOWN.is_set():
            try:
                tok = request(url=f'{base}/token', data={
                    'grantType': 'urn:ietf:params:oauth:grant-type:device_code',
                    'deviceCode': dev['deviceCode'],
                    'clientId': client_id,
                    'clientSecret': client_secret,
                    'scope': scopes,
                }).load()
            except HttpError as e:
                msg = e.response.body.decode()
                # Handle polling errors per RFC 8628 / service semantics
                if 'authorization_pending' in msg:
                    time.sleep(interval)
                    continue
                if 'slow_down' in msg:
                    interval += 1
                    time.sleep(interval)
                    continue
                if 'expired_token' in msg or 'access_denied' in msg:
                    raise error(msg)
                # Other HTTP errors
                raise error(msg)
            else:
                # print('tok', tok)
                with LOCK:
                    cls.SSO_SESSION = _ = {
                        **tok,
                        'issuedAt': now().isoformat(),
                        'region': region,
                        'startUrl': start_url,
                        'scopes': scopes,
                        'clientId': client_id,
                        'clientSecret': client_secret,
                        # 'deviceCode': dev['deviceCode'],
                    }
                cls.update_accounts(session=cls.SSO_SESSION)
                return _

        if now() > expires_at:
            raise error('Timed out waiting for authorization.')
        else:
            raise error('Aborted.')

    @classmethod
    def get_role_session(cls, account_id, role_name, region=None):
        if session := cls.get_sso_session(create=True):
            if data := cls.portal(
                    path='/federation/credentials',
                    token=session['accessToken'],
                    region=session['region'],
                    account_id=account_id,
                    role_name=role_name,
            ):
                rc = data.get('roleCredentials') or {}
                if not rc:
                    raise RuntimeError("No roleCredentials in response")
                exp = dt.datetime.fromtimestamp(rc['expiration'] / 1000, tz=dt.timezone.utc)
                print(exp)
                print(exp - now())
                return {
                    'AWS_ACCESS_KEY_ID': rc['accessKeyId'],
                    'AWS_SECRET_ACCESS_KEY': rc['secretAccessKey'],
                    'AWS_SESSION_TOKEN': rc['sessionToken'],
                    # 'AWS_CREDENTIAL_EXPIRATION': _utc_iso(rc['expiration']),
                    'AWS_REGION': (_ := region or session['region']),
                    'AWS_DEFAULT_REGION': _,
                    'AWS_ACCOUNT': account_id,
                }
        return None

    @classmethod
    def list_profiles(cls):
        conf = cls.load_aws_config()
        print('sso-sessions:')
        for k, v in conf.get('sso-session', {}).items():
            print(f'  {k}:')
            for k, v in v.items():
                print(f'    {k}: {v}')
        print('profiles:')
        for _ in sorted(conf.get('profile', {})):
            print(f'  {_}:')
            for k, v in cls.get_profile_config(name=_, resolve=False).items():
                if v.startswith('0'):
                    v = f'"{v}"'
                print(f'    {k}: {v}')

    @classmethod
    def start(cls):
        subprocess.Popen(
            sys.argv[:1] + ['serve'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,  # start in a new session
        )

    @classmethod
    def stop(cls):
        if _ := cls.get():
            _, = _
            os.kill(int(_['pid']), signal.SIGTERM)

    @classmethod
    def get(cls):
        return [p for p in lsof(port=f'TCP:{PORT}') or [] if p['name'] == f'*:{PORT}']

    @classmethod
    def is_running(cls):
        return bool(cls.get())


class Client:
    @classmethod
    def send(cls, data):
        while True and not SHUTDOWN.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((HOST, PORT))
            except Exception as e:
                if 'Connection refused' not in str(e):
                    print(e)
                wait(0.5)
            else:
                # print("-->", data)
                s.sendall(json.dumps(data).encode())

                r = s.recv(4196)
                # print("<--", r.decode().strip() or '(none)')

                s.close()
                return r

    @classmethod
    def auth(cls, *args, **kwargs):
        _ = cls.send(args)
        try:
            _ = json.loads(_)
        except Exception as e:
            raise error(f"{e} {_}")
        else:
            if kwargs.get('boto3'):
                import boto3
                from botocore.exceptions import ClientError
                _ = boto3.Session(
                    aws_session_token=_['AWS_SESSION_TOKEN'],
                    aws_secret_access_key=_['AWS_SECRET_ACCESS_KEY'],
                    aws_access_key_id=_['AWS_ACCESS_KEY_ID'],
                    region_name=_['AWS_REGION'],
                )
                _.Error = ClientError
                return _


class API:
    @classmethod
    def sigv4_api(
        cls,
        *,
        service: str = None,
        method: str = 'GET',
        region: Optional[str] = None,
        host: Optional[str] = None,           # e.g. "execute-api.us-east-1.amazonaws.com" (if None -> "{service}.{region}.amazonaws.com")
        path: str = "/",                        # canonical path, already URL-encoded where necessary
        query: Optional[Union[str, Mapping[str, Union[str, int, Sequence[Union[str, int]]]]]] = None,  # dict or raw query string
        headers: Optional[Mapping[str, str]] = None,   # additional headers (e.g. {"Content-Type": "...", "X-Amz-Target": "..."} )
        body: Optional[Union[bytes, str, Mapping]] = None,  # bytes | str | JSON-serializable (auto-serialized if Content-Type is JSON)
        timeout: Optional[float] = None,
        access_key: str = None,
        secret_key: str = None,
        session_token: str = None,
    ) -> Response:
        access_key = access_key or os.getenv('AWS_ACCESS_KEY_ID')
        secret_key = secret_key or os.getenv('AWS_SECRET_ACCESS_KEY')
        session_token = session_token or os.getenv('AWS_SESSION_TOKEN')
        if host:
            _ = host.split('.')
            service = service or _[-4]
            region = region or _[-3]
        if not region:
            region = os.getenv('AWS_REGION') or os.getenv('AWS_DEFAULT_REGION')
        assert service and region

        # --- Endpoint/host ---
        _host = host or f"{service}.{region}.amazonaws.com"
        scheme = "https"
        # Build querystring (raw or from mapping)
        canonical_qs, url_qs = cls._build_qs(query)
        endpoint = f"{scheme}://{_host}{path}{url_qs}"

        # --- Body handling & Content-Type defaulting ---
        req_headers: Dict[str, str] = {}
        if headers:
            # copy without changing case here; canonicalization happens later with lowercasing
            req_headers.update(headers)

        content_type = req_headers.get("Content-Type")
        if isinstance(body, (dict, list)):
            # If JSON given but no Content-Type, default to AWS JSON
            if not content_type:
                # Many AWS JSON services accept this content type
                content_type = "application/x-amz-json-1.1"
                req_headers["Content-Type"] = content_type
            body_bytes = json.dumps(body, separators=(",", ":")).encode()
        elif isinstance(body, str):
            body_bytes = body.encode()
        elif body is None:
            body_bytes = b""
        else:
            assert isinstance(body, bytes)
            body_bytes = body  # bytes

        # --- Dates ---
        amz_date = now().strftime("%Y%m%dT%H%M%SZ")
        datestamp = now().strftime("%Y%m%d")

        # --- Canonical request pieces ---
        # Required signing headers
        signing_headers = {
            "host": _host,
            "x-amz-date": amz_date,
            "x-amz-security-token": session_token,
        }

        # Bring in user headers (lowercased for signing), merging carefully
        if req_headers:
            for k, v in req_headers.items():
                lk = k.lower()
                # Normalize whitespace per AWS rules
                signing_headers[lk] = " ".join(str(v).strip().split())

        # Canonical headers/signed headers
        sorted_header_items = sorted(signing_headers.items())
        canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted_header_items)
        signed_headers = ";".join(k for k, _ in sorted_header_items)
        payload_hash = hashlib.sha256(body_bytes).hexdigest()

        def _canonical_uri(_: str) -> str:
            # Must be URI-encoded with safe "-_.~/"
            # Assume input is either raw or already encoded; encode only unsafe characters.
            return urllib.parse.quote(_ if _ else "/", safe="/-_.~")

        canonical_request = "\n".join([
            method.upper(),
            _canonical_uri(path),
            canonical_qs,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]).encode()

        # --- String to sign ---
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
        string_to_sign = "\n".join([
            algorithm, amz_date, credential_scope, hashlib.sha256(canonical_request).hexdigest(),
        ]).encode()

        # --- Derive signing key & signature ---
        def _hmac(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()

        k_date = _hmac(("AWS4" + secret_key).encode(), datestamp)
        k_region = _hmac(k_date, region)
        k_service = _hmac(k_region, service)
        k_signing = _hmac(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign, hashlib.sha256).hexdigest()

        # --- Final request headers (proper casing for network) ---
        final_headers = dict(req_headers) if req_headers else {}
        final_headers["Authorization"] = (
            f"{algorithm} Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        final_headers["X-Amz-Date"] = amz_date
        final_headers["x-amz-content-sha256"] = payload_hash
        final_headers["Host"] = _host
        if session_token:
            final_headers["X-Amz-Security-Token"] = session_token

        return request(
            method=method,
            url=endpoint,
            headers=final_headers,
            data=body_bytes if method.upper() != "GET" else None,
        )

    @classmethod
    def _build_qs(
        cls, query: Optional[Union[str, Mapping[str, Union[str, int, Sequence[Union[str, int]]]]]]
    ) -> Tuple[str, str]:
        """
        Returns (canonical_qs_for_signing, url_qs_for_request)
        Canonicalization per AWS: sort by key, then value; encode with safe '-_.~'
        """
        def _canonicalize_query_mapping(mapping: Mapping[str, Sequence[str]]) -> str:
            enc = lambda s: urllib.parse.quote(s, safe="-_.~")
            items = []
            for k, values in mapping.items():
                for v in values:
                    items.append((enc(k), enc(v)))
            # Sort by key, then value
            items.sort(key=lambda kv: (kv[0], kv[1]))
            return "&".join(f"{k}={v}" for k, v in items)

        if query is None:
            return "", ""
        if isinstance(query, str):
            # Use as-is for URL; for signing, we must canonicalize
            parsed = urllib.parse.parse_qs(query, keep_blank_values=True, strict_parsing=False)
            return _canonicalize_query_mapping(parsed), query
        # Mapping path
        # Normalize values to list of strings
        norm: Dict[str, Sequence[str]] = {}
        for k, v in query.items():
            if isinstance(v, (list, tuple)):
                norm[str(k)] = [str(x) for x in v]
            else:
                norm[str(k)] = [str(v)]
        canonical = _canonicalize_query_mapping(norm)
        # For URL query, we can use urllib to encode (order not strictly required for request URL)
        _items = []
        for k, values in norm.items():
            for val in values:
                _items.append((k, val))
        url_qs = '?' + urllib.parse.urlencode(_items, doseq=True, safe="-_.~") if _items else ''
        return canonical, url_qs

    @classmethod
    def json_api(
        cls,
        *,
        target: Optional[str],
        payload: Union[Mapping, Sequence, None],
        service: Optional[str] = None,
        region: Optional[str] = None,
        host: Optional[str] = None,
        uri: str = "/",
        method: str = "POST",
        timeout: Optional[float] = None,
    ) -> Response:
        """
        For AWS JSON RPC-style APIs (e.g., Secrets Manager, STS JSON variants, Comprehend, etc.).
        """
        if target and not service:
            service = target.split(".")[0]
        assert service
        headers = {"Content-Type": "application/x-amz-json-1.1"}
        if target:
            headers["X-Amz-Target"] = target
        return cls.sigv4_api(
            method=method,
            service=service,
            region=region,
            host=host,
            path=uri,
            headers=headers,
            body=payload if payload is not None else {},
            timeout=timeout,
        )

    @classmethod
    def query_api(
        cls,
        action: str,
        params: Optional[Mapping[str, Union[str, int, Sequence[Union[str, int]]]]] = None,
        region: Optional[str] = None,
        host: Optional[str] = None,
        version: Optional[str] = None,
        timeout: Optional[float] = None,
        access_key: str = None,
        secret_key: str = None,
        session_token: str = None,
    ) -> Response:
        """
        For AWS "Query" APIs (e.g., STS, IAM, CloudFormation, Route53, SNS, some older services).
        """
        service, action = action.split(":")
        q = dict(params or {})
        host = host or {'sts': f'sts.{region}.amazonaws.com'}[service]
        q["Version"] = version or {'sts': '2011-06-15'}[service]
        q["Action"] = action
        return cls.sigv4_api(
            method="POST",
            service=service,
            region=region,
            host=host,
            path="/",
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
            # Body must be the form-encoded params for Query APIs
            body=urllib.parse.urlencode(q, doseq=True, safe="-_.~"),
            timeout=timeout,
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
        )


@lru_cache(maxsize=None)
def get_secret(secret_id) -> str:
    return API.json_api(
        target='secretsmanager.GetSecretValue',
        payload={'SecretId': secret_id, 'VersionStage': 'AWSCURRENT'},
    ).load()['SecretString']


def authenticate(sso_id, sso_region, account_id, role_name, region=None):
    start_url = f'https://{sso_id}.awsapps.com/start'
    base = f'https://oidc.{sso_region}.amazonaws.com'

    scopes = ['sso:account:access']
    reg = request(url=f'{base}/client/register', data={
        'clientName': 'aws.py',
        'clientType': 'public',
        'scopes': scopes,
    }).load()
    client_id = reg['clientId']
    client_secret = reg['clientSecret']

    dev: Dict[str, Union[str, int]] = request(url=f'{base}/device_authorization', data={
        'clientId': client_id,
        'clientSecret': client_secret,
        'startUrl': start_url,
    }).load()

    print('Authorize:', dev['userCode'])
    os.system('open ' + dev['verificationUriComplete'])

    interval = dev['interval']
    expires_at = now() + dt.timedelta(seconds=dev['expiresIn'])

    # Poll /token until authorized or expired
    while now() < expires_at:
        session = request(url=f'{base}/token', data={
            'grantType': 'urn:ietf:params:oauth:grant-type:device_code',
            'deviceCode': dev['deviceCode'],
            'clientId': client_id,
            'clientSecret': client_secret,
            'scope': scopes,
        }).load()
        if msg := session.get('error'):
            # Handle polling errors per RFC 8628 / service semantics
            if 'authorization_pending' in msg:
                time.sleep(interval)
                continue
            if 'slow_down' in msg:
                interval += 1
                time.sleep(interval)
                continue
            if 'expired_token' in msg or 'access_denied' in msg:
                raise error(msg)
            # Other HTTP errors
            raise error(msg)
        else:
            if data := call_portal(
                path='/federation/credentials',
                token=session['accessToken'],
                region=sso_region,
                account_id=account_id,
                role_name=role_name,
            ):
                if rc := data.get('roleCredentials'):
                    os.environ.update({
                        'AWS_ACCESS_KEY_ID': rc['accessKeyId'],
                        'AWS_SECRET_ACCESS_KEY': rc['secretAccessKey'],
                        'AWS_SESSION_TOKEN': rc['sessionToken'],
                        'AWS_REGION': region or '',
                    })
                    return
                else:
                    raise error("No roleCredentials in response")

    if now() > expires_at:
        raise error('Timed out waiting for authorization.')
    else:
        raise error('Aborted.')


def call_portal(path, token, region, **query):
    while True:
        r = request(
            url=f'https://portal.sso.{region}.amazonaws.com' + path,
            headers={'Accept': 'application/json', 'x-amz-sso_bearer_token': token},
            query=query,
            timeout=30,
        )
        if r.status == 429:
            time.sleep(1)
            continue
        elif r.status > 300:
            raise error(f'Failed to connect to portal: {r.status}')
        return r.load()


def main():
    exe = sys.argv[0]
    args = sys.argv[1:]
    if os.getenv('DEBUG'):
        print('args', args, file=sys.stderr)
        print('server', Server.get(), file=sys.stderr)

    if not args:
        print('Example usage:')
        _ = f' - {exe} '
        print(_ + '$ACCOUNT_NAME [$ROLE_NAME] [$REGION] -- aws s3 ls')
        print(_ + '$ACCOUNT_ID -- aws sts get-caller-identity # uses read-only role by default')
        print(_ + '$POFILE -- aws ...  # uses profile from ~/.aws/config')
        print(_ + 'serve               # starts token server')
        print(_ + 'stop                # stops the server')
        print(_ + '-l                  # list SSO accounts and roles')
        print(_ + '-p                  # list profiles from ~/.aws/config')

    elif args in (['serve'], ['start']):
        Server.serve()

    elif args == ['stop']:
        Server.stop()

    elif args == ['-l']:
        if _ := Client.send(data=args).strip():
            print(_.decode())

    elif args == ['-p']:
        Server.list_profiles()

    elif '--' not in args:
        raise error('-- is missing in args')

    else:
        sso_args = []
        while args:
            if args[0] == '--':
                args = args[1:]
                break
            elif (_ := args.pop(0)) != 'exec':
                sso_args.append(_)

        if not Server.is_running():
            Server.start()

        if _ := Client.send(data=sso_args).strip():
            if _[:1] != b'{':  # note: cannot use _[0] here
                raise error(_.decode())
            os.environ.update(json.loads(_))
            proc = subprocess.Popen(
                args,
                env={'PYTHONUNBUFFERED': '1', 'FORCE_COLOR': '1', **os.environ, **json.loads(_)},
            )
            proc.wait()


if __name__ == '__main__':
    main()

__all__ = ['RX']
