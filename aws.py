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

HOST = '0.0.0.0'
PORT = 4550
PID = os.getpid()

LOCK = threading.Lock()
SHUTDOWN = threading.Event()

OIDC_URL = 'https://oidc.{}.amazonaws.com'
PORTAL_URL = 'https://portal.sso.{}.amazonaws.com'

AWS_CONFIG: Optional[configparser.ConfigParser] = None
AWS_CONFIG_PATH = pathlib.Path.home() / '.aws/config'
SSO_SESSION: Optional[dict[str, Any]] = None
AWS_ROLES: Optional[dict[tuple[str, str, str], Any]] = None


class RX:
    REGION = re.compile(r'(af|ap|ca|cn|eu|il|me|mx|sa|us)-(central|east|north|south|west)-\d')


def _shutdown(*_):
    SHUTDOWN.set()


signal.signal(signal.SIGINT, _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


def error(msg) -> Exception:
    print('Error:', msg, file=sys.stderr)
    sys.exit(1)


def load_aws_config():
    global AWS_CONFIG
    if AWS_CONFIG_PATH.exists():
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
            AWS_CONFIG = data
        return AWS_CONFIG
    else:
        raise error(f'File not found {AWS_CONFIG_PATH}')


def get_sso_config(name=None):
    name = name or os.getenv('AWS_SSO_SESSION')
    config = load_aws_config()

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


def get_profile_config(name, require=False, resolve=True):
    if c := load_aws_config().get('profile', {}).get(name):
        if resolve and (_ := c.pop('include_profile', None)):
            c = {**get_profile_config(_, require=True), **c}
        return c
    elif require:
        raise error(f'No [profile <name>] found in {AWS_CONFIG_PATH}')
    else:
        return None


def get_sso_session(create=False):
    print(get_sso_session)
    global SSO_SESSION
    if _ := SSO_SESSION:
        d = now() - dt.datetime.fromisoformat(_['issuedAt'])
        x = dt.timedelta(seconds=_['expiresIn'])
        if d > x:
            print(f'Session expired: {_["issuedAt"]} {_["expiresIn"]}')
            with LOCK:
                SSO_SESSION = None

        elif d > dt.timedelta(minutes=10):
            url = OIDC_URL.format(_['region']) + '/token'
            tok = post_json(url=url, payload={
                'grantType': 'refresh_token',
                'clientId': _['clientId'],
                'clientSecret': _['clientSecret'],
                'refreshToken': _['refreshToken'],
            })
            # print('ref', tok)
            with LOCK:
                SSO_SESSION = {**SSO_SESSION, **tok, 'issuedAt': (_ := now().isoformat())}
            update_accounts(session=SSO_SESSION)
            print('Session refreshed', _)
            return SSO_SESSION
        else:
            print('Session still valid for', int((x - d).total_seconds()), 'seconds')
            if update_accounts(session=SSO_SESSION):
                return SSO_SESSION
            else:
                print('Session signed out externally')
                with LOCK:
                    SSO_SESSION = None
    if not create:
        print('No active sso-session, not creating new one')
        return None

    print('Creating a new session')
    _ = get_sso_config()
    start_url = _['sso_start_url']
    region = _['sso_region']
    scopes: list[str] = _['sso_registration_scopes'].split()
    base = OIDC_URL.format(region)

    reg = post_json(f'{base}/client/register', {
        'clientName': 'aws.py',
        'clientType': 'public',
        'scopes': scopes,
    })
    client_id = reg['clientId']
    client_secret = reg['clientSecret']

    dev = post_json(f'{base}/device_authorization', {
        'clientId': client_id,
        'clientSecret': client_secret,
        'startUrl': start_url,
    })

    print('Authorize:', dev['userCode'])
    os.system('open ' + dev['verificationUriComplete'])

    interval = dev['interval']
    expires_at = now() + dt.timedelta(seconds=dev['expiresIn'])

    # Poll /token until authorized or expired
    while now() < expires_at and not SHUTDOWN.is_set():
        try:
            tok = post_json(f'{base}/token', {
                'grantType': 'urn:ietf:params:oauth:grant-type:device_code',
                'deviceCode': dev['deviceCode'],
                'clientId': client_id,
                'clientSecret': client_secret,
                'scope': scopes,
            })
        except RuntimeError as e:
            msg = str(e)
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
                SSO_SESSION = _ = {
                    **tok,
                    'issuedAt': now().isoformat(),
                    'region': region,
                    'startUrl': start_url,
                    'scopes': scopes,
                    'clientId': client_id,
                    'clientSecret': client_secret,
                    # 'deviceCode': dev['deviceCode'],
                }
            update_accounts(session=SSO_SESSION)
            return _

    if now() > expires_at:
        raise error('Timed out waiting for authorization.')
    else:
        raise error('Aborted.')


@dataclasses.dataclass
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def load(self) -> dict:
        if self.body.startswith(b"<"):
            return xml_to_dict(self.body)
        return json.loads(self.body)


def request(*, url, headers=None, method=None, query=None, data=None, timeout=None, raise_for_status=False) -> Response:
    headers = headers or {}
    if data and not isinstance(data, (bytes, str)):
        data = json.dumps(data).encode()
        headers.setdefault('Content-Type', 'application/json')
    if isinstance(data, str):
        data = data.encode()
    method = method or ('POST' if data is not None else 'GET')
    if query:
        url += '?' + urllib.parse.urlencode(query, safe='-_.~')
    req = urllib.request.Request(url=url, method=method.upper(), headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            headers = {k: v for k, v in resp.getheaders()}
            body = resp.read()
    except urllib.error.HTTPError as e:
        status = e.code
        headers = {k: v for k, v in e.headers.items()},
        body = e.read()
    if raise_for_status and status > 300:
        raise Exception(f"HTTP {status}: {body}")
    return Response(status=status, headers=headers, body=body)


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    print(url)
    req = urllib.request.Request(
        url=url,
        data=json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json'},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='ignore')
        raise RuntimeError(f'HTTP {e.code} POST {url}: {body}')


def portal(path, token, region, **query):
    while not SHUTDOWN.is_set():
        url = PORTAL_URL.format(region) + path
        if query:
            url += '?' + urllib.parse.urlencode(query, safe='-_.~')
        print(url)
        req = urllib.request.Request(
            url=url,
            headers={'Accept': 'application/json', 'x-amz-sso_bearer_token': token},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait(0.1)
                continue
            else:
                print(e)
                break
    return False


def get_accounts(session=None):
    if not session:
        session = SSO_SESSION
    if _ := portal(
        path='/assignment/accounts',
        token=session['accessToken'],
        region=session['region'],
        max_result=100,
    ):
        assert not _['nextToken'], _
        # there is also emailAddress
        return {a['accountId']: a['accountName'] for a in _['accountList']}
    return None


def get_roles(account_id, session=None):
    if not session:
        session = get_sso_session(create=True)
    if _ := portal(
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


async def gather_with_concurrency(n, coroutines):
    semaphore = asyncio.Semaphore(n)

    async def sem_coro(coroutine):
        async with semaphore:
            return await coroutine

    return await asyncio.gather(*(sem_coro(c) for c in coroutines))


async def get_roles_async(account_ids, session=None):
    assert isinstance(account_ids, (list, dict))
    if not session:
        session = get_sso_session(create=True)
    async def task(account_id):
        try:
            return account_id, await asyncio.to_thread(get_roles, account_id=account_id, session=session)
        except Exception as e:
            print(e)
            raise
    tasks = [task(account_id=_) for _ in account_ids]
    return dict(await gather_with_concurrency(10, tasks))


def update_accounts(session):
    if accounts := get_accounts(session=SSO_SESSION):
        with LOCK:
            session['accounts'] = accounts
        return accounts
    return False


def get_role_session(account_id, role_name, region=None):
    if session := get_sso_session(create=True):
        if data := portal(
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
            }
    return None


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


def verify_client(addr):
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


def wait(seconds):
    for _ in range(int(seconds * 10)):
        if not SHUTDOWN.is_set():
            time.sleep(0.1)


def refresher() -> None:
    while not SHUTDOWN.is_set():
        get_sso_session()
        wait(seconds=60)


def serve():
    get_sso_session(create=True)

    thread = threading.Thread(target=refresher, daemon=True)
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
                    if verify_client(addr):
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
                        accounts = get_sso_session(create=True)['accounts']
                        aliases = {v: k for k, v in accounts.items()}
                        account_id = role_name = duration = region = None

                        if _args == ['-l']:
                            account_roles = asyncio.run(get_roles_async(account_ids=accounts))
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
                        if len(_args) == 1 and (p := get_profile_config(_args[0])):
                            print(p)
                            while _ := p.get('source_profile'):
                                if _ in chain:
                                    break
                                chain[_] = p
                                p = get_profile_config(_)
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

                        roles = get_roles(account_id=account_id)
                        if role_name not in roles:
                            _sendall(f"Invalid role name {role_name}, allowed: {roles}")
                        else:
                            ss = get_role_session(account_id=account_id, role_name=role_name, region=region)
                            while chain:
                                k, _ = chain.popitem()
                                print("CHAIN:", k)
                                _ = query_api(
                                    action="sts:AssumeRole",
                                    params={"RoleArn": _['role_arn'], "RoleSessionName": k},
                                    region=(region := _.get('region') or region),
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
                                }
                            _sendall(json.dumps(ss))
    finally:
        SHUTDOWN.set()
        thread.join()


def send(data):
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


def auth(*args, **kwargs):
    _ = send(args)
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


def start_server():
    subprocess.Popen(
        sys.argv[:1] + ['serve'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,  # start in a new session
    )


def get_server():
    return [p for p in lsof(port=f'TCP:{PORT}') or [] if p['name'] == f'*:{PORT}']


def stop_server():
    if _ := get_server():
        _, = _
        os.kill(int(_['pid']), signal.SIGTERM)


def is_running():
    return bool(get_server())


def main():
    exe = sys.argv[0]
    args = sys.argv[1:]
    if os.getenv('DEBUG'):
        print('args', args, file=sys.stderr)
        print('server', get_server(), file=sys.stderr)

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
        serve()

    elif args == ['stop']:
        stop_server()

    elif args == ['-l']:
        if _ := send(data=args).strip():
            print(_.decode())

    elif args == ['-p']:
        conf = load_aws_config()
        print('sso-sessions:')
        for k, v in conf.get('sso-session', {}).items():
            print(f'  {k}:')
            for k, v in v.items():
                print(f'    {k}: {v}')
        print('profiles:')
        for _ in sorted(conf.get('profile', {})):
            print(f'  {_}:')
            for k, v in get_profile_config(name=_, resolve=False).items():
                if v.startswith('0'):
                    v = f'"{v}"'
                print(f'    {k}: {v}')

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

        if not is_running():
            start_server()

        if _ := send(data=sso_args).strip():
            if _[:1] != b'{':
                raise error(_.decode())
            os.environ.update(json.loads(_))
            proc = subprocess.Popen(
                args,
                env={'PYTHONUNBUFFERED': '1', 'FORCE_COLOR': '1', **os.environ, **json.loads(_)},
            )
            proc.wait()


@lru_cache(maxsize=None)
def get_secret(secret_id) -> str:
    return json_api(
        target='secretsmanager.GetSecretValue',
        payload={'SecretId': secret_id, 'VersionStage': 'AWSCURRENT'},
    ).load()['SecretString']


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


def sigv4_api(
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
    canonical_qs, url_qs = _build_qs(query)
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


def _build_qs(
    query: Optional[Union[str, Mapping[str, Union[str, int, Sequence[Union[str, int]]]]]]
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


def json_api(
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
    return sigv4_api(
        method=method,
        service=service,
        region=region,
        host=host,
        path=uri,
        headers=headers,
        body=payload if payload is not None else {},
        timeout=timeout,
    )


def query_api(
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
    return sigv4_api(
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


__all__ = ['RX']


if __name__ == '__main__':
    main()
