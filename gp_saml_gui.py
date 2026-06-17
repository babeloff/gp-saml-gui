#!/usr/bin/env python3

import warnings
try:
    import gi

    gi.require_version('Gtk', '3.0')
    try:
        gi.require_version('WebKit2', '4.1')
    except ValueError:  # I wish this were ImportError
        gi.require_version('WebKit2', '4.0')
        warnings.warn("Using WebKit2Gtk 4.0 (obsolete); please upgrade to WebKit2Gtk 4.1")
    from gi.repository import Gtk, WebKit2, GLib
except ImportError:
    try:
        import pgi as gi
        gi.require_version('Gtk', '3.0')
        gi.require_version('WebKit2', '4.0')
        from pgi.repository import Gtk, WebKit2, GLib
        warnings.warn("Using PGI and WebKit2Gtk 4.0 (both obsolete); please upgrade to PyGObject and WebKit2Gtk 4.1")
    except ImportError:
        gi = None
if gi is None:
    raise ImportError("Either gi (PyGObject) or pgi (obsolete) module is required.")

import argparse
import urllib3
import requests
import xml.etree.ElementTree as ET
import ssl
import tempfile

from operator import setitem
from os import path, dup2, execvp, environ
from shlex import quote
from sys import stderr, platform
from binascii import a2b_base64, b2a_base64
from urllib.parse import urlparse, urlencode, urlunsplit, unquote
from html.parser import HTMLParser


class CommentHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.comments = []

    def handle_comment(self, data: str) -> None:
        self.comments.append(data)


COOKIE_FIELDS = ('prelogin-cookie', 'portal-userauthcookie')


class SAMLLoginView:
    def __init__(self, uri, html, args):

        Gtk.init(None)
        self.window = window = Gtk.Window()

        # API reference: https://lazka.github.io/pgi-docs/#WebKit2-4.0

        self.closed = False
        self.success = False
        self.saml_result = {}
        self.verbose = args.verbose
        self.server = args.server

        self.ctx = WebKit2.WebContext.get_default()
        if not args.verify:
            self.ctx.set_tls_errors_policy(WebKit2.TLSErrorsPolicy.IGNORE)
        self.cookies = self.ctx.get_cookie_manager()
        if args.cookies:
            self.cookies.set_accept_policy(WebKit2.CookieAcceptPolicy.ALWAYS)
            self.cookies.set_persistent_storage(args.cookies, WebKit2.CookiePersistentStorage.TEXT)
        self.wview = WebKit2.WebView()

        if args.no_proxy:
            data_manager = self.ctx.get_website_data_manager()
            data_manager.set_network_proxy_settings(WebKit2.NetworkProxyMode.NO_PROXY, None)

        if args.user_agent is None:
            args.user_agent = 'PAN GlobalProtect'
        settings = self.wview.get_settings()
        settings.set_user_agent(args.user_agent)
        settings.set_enable_javascript(True)
        settings.set_enable_javascript_markup(True)
        self.wview.set_settings(settings)

        window.resize(500, 500)
        window.add(self.wview)
        window.show_all()
        window.set_title("SAML Login")
        window.connect('delete-event', self.close)
        self.wview.connect('load-changed', self.on_load_changed)
        self.wview.connect('resource-load-started', self.log_resources)
        self.wview.connect('notify::uri', self.on_uri_changed)
        self.wview.connect('decide-policy', self.on_decide_policy)

        if html:
            self.wview.load_html(html, uri)
        else:
            self.wview.load_uri(uri)

    def close(self, window, event):
        self.closed = True
        Gtk.main_quit()

    def log_resources(self, webview, resource, request):
        if self.verbose > 1:
            print('[REQUEST] %s for resource %s' % (request.get_http_method() or 'Request', resource.get_uri()), file=stderr)
        if self.verbose > 2:
            resource.connect('finished', self.log_resource_details, request)

    def log_resource_details(self, resource, request):
        m = request.get_http_method() or 'Request'
        uri = resource.get_uri()
        rs = resource.get_response()
        h = rs.get_http_headers() if rs else None
        if h:
            ct, cl = h.get_content_type(), h.get_content_length()
            content_type = ct[0]
            charset = ct.params.get('charset') if ct.params else None
            content_details = '%d bytes of %s%s for ' % (cl, content_type, ('; charset='+charset) if charset else '')
        print('[RECEIVE] %sresource %s %s' % (content_details if h else '', m, uri), file=stderr)

    def log_resource_text(self, resource, result, content_type, charset=None, show_headers=None):
        data = resource.get_data_finish(result)
        content_details = '%d bytes of %s%s for ' % (len(data), content_type, ('; charset='+charset) if charset else '')
        print('[DATA   ] %sresource %s' % (content_details, resource.get_uri()), file=stderr)
        if show_headers:
            for h,v in show_headers.items():
                print('%s: %s' % (h, v), file=stderr)
            print(file=stderr)
        if charset or content_type.startswith('text/'):
            print(data.decode(charset or 'utf-8'), file=stderr)

    def on_uri_changed(self, webview, param):
        uri = webview.get_uri()
        if self.verbose and uri:
            print('[NAV    ] URI changed → %s' % uri, file=stderr)

    def on_decide_policy(self, webview, decision, decision_type):
        if decision_type == WebKit2.PolicyDecisionType.NAVIGATION_ACTION:
            action = decision.get_navigation_action()
            req = action.get_request()
            method = req.get_http_method() or 'Request'
            uri = req.get_uri()
            if self.verbose:
                print('[POLICY ] Navigation %s → %s' % (method, uri), file=stderr)
            if uri.startswith('globalprotectcallback:'):
                self._handle_cas_callback(uri)
                decision.ignore()
                return True
            decision.use()
            return True
        return False

    def _handle_cas_callback(self, uri):
        """Parse globalprotectcallback:cas-as=1&un=...&token=... and store auth result."""
        qs = uri[len('globalprotectcallback:'):]
        params = {}
        for part in qs.split('&'):
            k, _, v = part.partition('=')
            if k:
                params[k] = unquote(v)

        username = params.get('un', '')
        token = params.get('token', '')

        if not username or not token:
            print('[SAML   ] CAS callback missing un or token', file=stderr)
            return

        if self.verbose:
            print('[SAML   ] Got CAS callback: un=%s cas-as=%s' % (username, params.get('cas-as', '?')), file=stderr)

        self.saml_result['saml-username'] = username
        self.saml_result['portal-userauthcookie'] = token
        self.saml_result['cas-as'] = params.get('cas-as', '1')
        self.saml_result['server'] = self.server
        self.check_done()

    def on_load_changed(self, webview, event):
        event_names = {
            WebKit2.LoadEvent.STARTED:     'STARTED',
            WebKit2.LoadEvent.REDIRECTED:  'REDIRECT',
            WebKit2.LoadEvent.COMMITTED:   'COMMIT ',
            WebKit2.LoadEvent.FINISHED:    'FINISH ',
        }
        if self.verbose > 1:
            uri = webview.get_uri() or '(none)'
            print('[LOAD   ] %s %s' % (event_names.get(event, str(event)), uri), file=stderr)

        if event != WebKit2.LoadEvent.FINISHED:
            return

        mr = webview.get_main_resource()
        uri = mr.get_uri()
        rs = mr.get_response()
        h = rs.get_http_headers() if rs else None
        ct = h.get_content_type() if h else None

        if self.verbose:
            print('[PAGE   ] Finished loading page %s' % uri, file=stderr)
        urip = urlparse(uri)
        origin = '%s %s' % ('🔒' if urip.scheme == 'https' else '🔴', urip.netloc)
        self.window.set_title("SAML Login (%s)" % origin)

        # if no response or no headers (for e.g. about:blank), skip checking this
        if not rs or not h:
            return

        # convert to normal dict
        d = {}
        h.foreach(lambda k, v: setitem(d, k.lower(), v))
        # filter to interesting headers (direct response headers)
        fd = {name: v for name, v in d.items() if name.startswith('saml-') or name in COOKIE_FIELDS}
        # also check Set-Cookie for portal cookies delivered as HTTP cookies
        set_cookie = d.get('set-cookie', '')
        for field in COOKIE_FIELDS:
            if field not in fd and field + '=' in set_cookie:
                for part in set_cookie.split(';'):
                    part = part.strip()
                    if part.lower().startswith(field + '='):
                        fd[field] = part[len(field)+1:]
                        if self.verbose:
                            print('[SAML   ] Found %s in Set-Cookie header' % field, file=stderr)
                        break

        if fd:
            if self.verbose:
                print("[SAML   ] Got SAML result headers: %r" % fd, file=stderr)
                if self.verbose > 1:
                    # display everything we found
                    mr.get_data(None, self.log_resource_text, ct[0], ct.params.get('charset'), d)
            self.saml_result.update(fd, server=urlparse(uri).netloc)
            self.check_done()

        if not self.success:
            if self.verbose > 1:
                print("[SAML   ] No headers in response, searching body for xml comments", file=stderr)
            # asynchronous call to fetch body content, continue processing in callback:
            mr.get_data(None, self.response_callback, ct)

    def response_callback(self, resource, result, ct):
        data = resource.get_data_finish(result)
        content = data.decode(ct.params.get("charset") or "utf-8")

        html_parser = CommentHtmlParser()
        html_parser.feed(content)

        fd = {}
        for comment in html_parser.comments:
            if self.verbose > 1:
                print("[SAML   ] Found comment in response body: '%s'" % comment, file=stderr)
            try:
                # xml parser requires valid xml with a single root tag, but our expected content
                # is just a list of data tags, so we need to improvise
                xmlroot = ET.fromstring("<fakexmlroot>%s</fakexmlroot>" % comment)
                # search for any valid first level xml tags (inside our fake root) that could contain SAML data
                for elem in xmlroot:
                    if elem.tag.startswith("saml-") or elem.tag in COOKIE_FIELDS:
                        fd[elem.tag] = elem.text
            except ET.ParseError:
                pass  # silently ignore any comments that don't contain valid xml

        if self.verbose > 1:
            print("[SAML   ] Finished parsing response body for %s" % resource.get_uri(), file=stderr)
        if fd:
            if self.verbose:
                print("[SAML   ] Got SAML result tags: %s" % fd, file=stderr)
            self.saml_result.update(fd, server=urlparse(resource.get_uri()).netloc)

        if not self.check_done():
            # Work around timing/race condition by retrying check_done after 1 second
            GLib.timeout_add(1000, self.check_done)

    def check_done(self):
        d = self.saml_result
        if 'saml-username' in d and ('prelogin-cookie' in d or 'portal-userauthcookie' in d):
            if self.verbose:
                print("[SAML   ] Got all required SAML headers, done.", file=stderr)
            self.success = True
            Gtk.main_quit()
            return True


class TLSAdapter(requests.adapters.HTTPAdapter):
    '''Adapt to older TLS stacks that would raise errors otherwise.

    We try to work around different issues:
    * Enable weak ciphers such as 3DES or RC4, that have been disabled by default
      in OpenSSL 3.0 or recent Linux distributions.
    * Enable weak Diffie-Hellman key exchange sizes.
    * Enable unsafe legacy renegotiation for servers without RFC 5746 support.

    See Also
    --------
    https://github.com/psf/requests/issues/4775#issuecomment-478198879

    Notes
    -----
    Python is missing an ssl.OP_LEGACY_SERVER_CONNECT constant.
    We have extracted the relevant value from <openssl/ssl.h>.

    '''

    def __init__(self, verify=True):
        self.verify = verify
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.set_ciphers('DEFAULT:@SECLEVEL=1')
        ssl_context.options |= 1<<2  # OP_LEGACY_SERVER_CONNECT

        if not self.verify:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        if hasattr(ssl_context, "keylog_filename"):
            sslkeylogfile = environ.get("SSLKEYLOGFILE")
            if sslkeylogfile:
                ssl_context.keylog_filename = sslkeylogfile

        self.poolmanager = urllib3.PoolManager(
                num_pools=connections,
                maxsize=maxsize,
                block=block,
                ssl_context=ssl_context)

def parse_args(args = None):
    pf2clientos = dict(linux='Linux', darwin='Mac', win32='Windows', cygwin='Windows')
    clientos2ocos = dict(Linux='linux-64', Mac='mac-intel', Windows='win')
    default_clientos = pf2clientos.get(platform, 'Windows')

    p = argparse.ArgumentParser()
    p.add_argument('server', help='GlobalProtect server (portal or gateway)')
    p.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-C', '--cookies', default='~/.gp-saml-gui-cookies',
                   help='Use and store cookies in this file (instead of default %(default)s)')
    x.add_argument('-K', '--no-cookies', dest='cookies', action='store_const', const=None,
                   help="Don't use or store cookies at all")
    x = p.add_mutually_exclusive_group()
    p.add_argument('-i', '--ignore-redirects', action='store_true', help='Use specified gateway hostname as server, ignoring redirects')
    x.add_argument('-g','--gateway', dest='interface', action='store_const', const='gateway', default='portal',
                   help='SAML auth to gateway')
    x.add_argument('-p','--portal', dest='interface', action='store_const', const='portal',
                   help='SAML auth to portal (default)')
    g = p.add_argument_group('Client certificate')
    g.add_argument('-c','--cert', help='PEM file containing client certificate (and optionally private key)')
    g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
    g = p.add_argument_group('Debugging and advanced options')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-v','--verbose', default=1, action='count', help='Increase verbosity of explanatory output to stderr')
    x.add_argument('-q','--quiet', dest='verbose', action='store_const', const=0, help='Reduce verbosity to a minimum')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-x','--external', action='store_true', help='Launch external browser (for debugging)')
    x.add_argument('-P','--pkexec-openconnect', action='store_const', dest='exec', const='pkexec', help='Use PolicyKit to exec openconnect')
    x.add_argument('-S','--sudo-openconnect', action='store_const', dest='exec', const='sudo', help='Use sudo to exec openconnect')
    x.add_argument('-E','--exec-openconnect', action='store_const', dest='exec', const='exec', help='Execute openconnect directly (advanced users)')
    g.add_argument('-u','--uri', action='store_true', help='Treat server as the complete URI of the SAML entry point, rather than GlobalProtect server')
    g.add_argument('--clientos', choices=set(pf2clientos.values()), default=default_clientos, help="clientos value to send (default is %(default)s)")
    g.add_argument('--clientver', type=int, default=6000, help="clientVer value to send in prelogin request (default %(default)s; use 4100 for older servers)")
    p.add_argument('-f','--field', dest='extra', action='append', default=[],
                   help='Extra form field(s) to pass to include in the login query string (e.g. "-f magic-cookie-value=deadbeef01234567")')
    p.add_argument('--allow-insecure-crypto', dest='insecure', action='store_true',
                   help='Allow use of insecure renegotiation or ancient 3DES and RC4 ciphers')
    p.add_argument('--user-agent', '--useragent', default='PAN GlobalProtect',
                   help='Use the provided string as the HTTP User-Agent header (default is %(default)r, as used by OpenConnect)')
    p.add_argument('--no-proxy', action='store_true', help='Disable system proxy settings')
    p.add_argument('openconnect_extra', nargs='*', help="Extra arguments to include in output OpenConnect command-line")
    args = p.parse_args(args)

    args.ocos = clientos2ocos[args.clientos]
    args.extra = dict(x.split('=', 1) for x in args.extra)

    if args.cookies:
        args.cookies = path.expanduser(args.cookies)

    if args.cert and args.key:
        args.cert, args.key = (args.cert, args.key), None
    elif args.cert:
        args.cert = (args.cert, None)
    elif args.key:
        p.error('--key specified without --cert')
    else:
        args.cert = None

    return p, args

def _cas_getconfig(s, server, un, cv, args):
    """POST portal cookie to getconfig.esp (no prelogin needed) and return best gateway address.

    For the CAS flow the server delivers the real portal-userauthcookie as an HTTP
    Set-Cookie on SAML20/SP/ACS, stored in the WebKit2 cookie file.  The JWT in the
    globalprotectcallback: URL is for the native GP client only and is rejected by
    getconfig.esp.  We prefer the cookie-file value; the JWT is a last resort.
    """
    import http.cookiejar

    endpoint = 'https://{}/global-protect/getconfig.esp'.format(server)

    # Try to find the real portal-userauthcookie in the WebKit2 cookie file.
    # This is the Set-Cookie value from SAML20/SP/ACS, not the JWT.
    portal_cookie = cv   # fallback: the JWT itself
    if args.cookies and path.exists(args.cookies):
        cj = http.cookiejar.MozillaCookieJar()
        try:
            cj.load(args.cookies, ignore_discard=True, ignore_expires=True)
            for c in cj:
                if c.name == 'portal-userauthcookie' and server in (c.domain or ''):
                    portal_cookie = c.value
                    if args.verbose:
                        print('[CAS    ] Found portal-userauthcookie in browser cookie jar', file=stderr)
                    break
            # Also inject all browser cookies into the session so the server sees them
            s.cookies.update({c.name: c.value for c in cj})
        except Exception as ex:
            if args.verbose:
                print('[CAS    ] Could not load cookie file %s: %s' % (args.cookies, ex), file=stderr)

    data = {
        'user': un,
        'passwd': '',
        'clientos': args.clientos,
        'os-version': args.clientos,
        'computer': 'localhost',
        'cas-as': '1',
        'portal-userauthcookie': portal_cookie,
    }
    if args.verbose:
        src = 'browser-cookie' if portal_cookie != cv else 'jwt-token'
        print('[CAS    ] POSTing to %s (source=%s)...' % (endpoint, src), file=stderr)
    try:
        res = s.post(endpoint, data=data, verify=args.verify)
        if args.verbose:
            print('[CAS    ] getconfig.esp HTTP %d, %d bytes' % (res.status_code, len(res.content)), file=stderr)
        if not res.content:
            print('[CAS    ] getconfig.esp returned empty body — cookie may be expired or wrong format', file=stderr)
            return None
        xml = ET.fromstring(res.content)
    except Exception as ex:
        print('[CAS    ] getconfig.esp failed: %s' % ex, file=stderr)
        return None

    status = xml.find('status')
    if status is not None and status.text.lower() != 'success':
        msg = xml.find('msg')
        print('[CAS    ] getconfig.esp error: %s' % (msg.text if msg is not None else 'unknown'), file=stderr)
        return None

    # Prefer the first external gateway by priority order; fall back to any entry/@name
    for gw in xml.findall('.//gateways/external/list/entry'):
        addr = gw.get('name')
        if addr:
            if args.verbose:
                print('[CAS    ] Using gateway: %s' % addr, file=stderr)
            return addr

    if args.verbose:
        print('[CAS    ] No gateways found in getconfig.esp response; falling back', file=stderr)
    return None


def main(args = None):
    p, args = parse_args(args)

    s = requests.Session()
    if args.insecure:
        s.mount('https://', TLSAdapter(verify=args.verify))
    s.headers['User-Agent'] = 'PAN GlobalProtect' if args.user_agent is None else args.user_agent
    s.cert = args.cert

    if2prelogin = {'portal':'global-protect/prelogin.esp','gateway':'ssl-vpn/prelogin.esp'}
    if2auth = {'portal':'global-protect/getconfig.esp','gateway':'ssl-vpn/login.esp'}

    # query prelogin.esp and parse SAML bits
    if args.uri:
        sam, uri, html = 'URI', args.server, None
    else:
        endpoint = 'https://{}/{}'.format(args.server, if2prelogin[args.interface])
        data = {'tmp':'tmp', 'kerberos-support':'yes', 'ipv6-support':'yes', 'clientVer':args.clientver, 'clientos':args.clientos, **args.extra}
        if args.verbose:
            print("Looking for SAML auth tags in response to %s..." % endpoint, file=stderr)
        try:
            res = s.post(endpoint, verify=args.verify, params=data)
        except Exception as ex:
            rootex = ex
            while True:
                if isinstance(rootex, ssl.SSLError):
                    break
                elif not rootex.__cause__ and not rootex.__context__:
                    break
                rootex = rootex.__cause__ or rootex.__context__
            if isinstance(rootex, ssl.CertificateError):
                p.error("SSL certificate error (try --no-verify to ignore): %s" % rootex)
            elif isinstance(rootex, ssl.SSLError):
                p.error("SSL error (try --allow-insecure-crypto to ignore): %s" % rootex)
            else:
                raise
        xml = ET.fromstring(res.content)
        if xml.tag != 'prelogin-response':
            p.error("This does not appear to be a GlobalProtect prelogin response\nCheck in browser: {}?{}".format(endpoint, urlencode(data)))
        status = xml.find('status')
        if status != None and status.text != 'Success':
            msg = xml.find('msg')
            if msg != None and msg.text == 'GlobalProtect {} does not exist'.format(args.interface):
                p.error("{} interface does not exist; specify {} instead".format(
                    args.interface.title(), '--portal' if args.interface=='gateway' else '--gateway'))
            else:
                p.error("Error in {} prelogin response: {}".format(args.interface, msg.text))
        sam = xml.find('saml-auth-method')
        sr = xml.find('saml-request')
        if sam is None or sr is None:
            p.error("{} prelogin response does not contain SAML tags (<saml-auth-method> or <saml-request> missing)\n\n"
                    "Things to try:\n"
                    "1) Spoof an officially supported OS (e.g. --clientos=Windows or --clientos=Mac)\n"
                    "2) Check in browser: {}?{}".format(args.interface.title(), endpoint, urlencode(data)))
        sam = sam.text
        sr = a2b_base64(sr.text).decode()
        if sam == 'POST':
            html, uri = sr, None
        elif sam == 'REDIRECT':
            uri, html = sr, None
        else:
            p.error("Unknown SAML method (%s)" % sam)

    # launch external browser for debugging
    if args.external:
        print("Got SAML %s, opening external browser for debugging..." % sam, file=stderr)
        import webbrowser
        if html:
            uri = 'data:text/html;base64,' + b2a_base64(html.encode()).decode()
        webbrowser.open(uri)
        raise SystemExit

    # spawn WebKit view to do SAML interactive login
    if args.verbose:
        print("Got SAML %s, opening browser..." % sam, file=stderr)
    slv = SAMLLoginView(uri, html, args)
    Gtk.main()
    if slv.closed:
        print("Login window closed by user.", file=stderr)
        p.exit(1)
    if not slv.success:
        p.error('''Login window closed without producing SAML cookies.''')

    # extract response and convert to OpenConnect command-line
    un = slv.saml_result.get('saml-username')
    if args.ignore_redirects:
        server = args.server
    else:
        server = slv.saml_result.get('server', args.server)

    for cn, ifh in (('prelogin-cookie','gateway'), ('portal-userauthcookie','portal')):
        cv = slv.saml_result.get(cn)
        if cv:
            break
    else:
        cn = ifh = None
        p.error("Didn't get an expected cookie. Something went wrong.")

    # CAS flows deliver a JWT via globalprotectcallback: — openconnect's portal path always
    # does a fresh prelogin.esp (hardcoded clientVer=4100) before submitting the cookie,
    # which the server rejects. Instead, POST the JWT directly to getconfig.esp (no prelogin
    # required) to learn the gateway address, then connect to the gateway directly.
    cas_gateway = None
    if cn == 'portal-userauthcookie' and cv.startswith('eyJ'):
        cas_gateway = _cas_getconfig(s, server, un, cv, args)

    if cas_gateway:
        urlpath = 'gateway:prelogin-cookie'
        openconnect_args = [
            "--protocol=gp",
            "--user="+un,
            "--os="+args.ocos,
            "--usergroup="+urlpath,
            "--passwd-on-stdin",
            cas_gateway,
        ] + args.openconnect_extra
    else:
        urlpath = args.interface + ":" + cn
        openconnect_args = [
            "--protocol=gp",
            "--user="+un,
            "--os="+args.ocos,
            "--usergroup="+urlpath,
            "--passwd-on-stdin",
            server,
        ] + args.openconnect_extra

    if args.insecure:
        openconnect_args.insert(1, "--allow-insecure-crypto")
    if args.user_agent:
        openconnect_args.insert(1, "--useragent="+args.user_agent)
    if args.cert:
        cert, key = args.cert
        if key:
            openconnect_args.insert(1, "--sslkey="+key)
        openconnect_args.insert(1, "--certificate="+cert)
    if args.no_proxy:
        openconnect_args.insert(1, "--no-proxy")

    openconnect_command = '''    echo {} |\n        sudo openconnect {}'''.format(
        quote(cv), " ".join(map(quote, openconnect_args)))

    if args.verbose:
        # Warn about ambiguities
        if server != args.server and not args.uri:
            if args.ignore_redirects:
                print('''IMPORTANT: During the SAML auth, you were redirected from {0} to {1}. This probably '''
                      '''means you should specify {1} as the server for final connection, but we're not 100% '''
                      '''sure about this. You should probably try both; if necessary, use the '''
                      '''--ignore-redirects option to specify desired behavior.\n'''.format(args.server, server), file=stderr)
            else:
                print('''IMPORTANT: During the SAML auth, you were redirected from {0} to {1}, however the '''
                      '''redirection was ignored because you specified --ignore-redirects.\n'''.format(args.server, server), file=stderr)
        if ifh != args.interface and not args.uri:
            print('''IMPORTANT: We started with SAML auth to the {} interface, but received a cookie '''
                  '''that's often associated with the {} interface. You should probably try both.\n'''.format(args.interface, ifh),
                  file=stderr)
        print('''\nSAML response converted to OpenConnect command line invocation:\n''', file=stderr)
        print(openconnect_command, file=stderr)

        print('''\nSAML response converted to test-globalprotect-login.py invocation:\n''', file=stderr)
        print('''    test-globalprotect-login.py --user={} --clientos={} -p '' \\\n         https://{}/{} {}={}\n'''.format(
            quote(un), quote(args.clientos), quote(server), quote(if2auth[args.interface]), quote(cn), quote(cv)), file=stderr)

    if args.exec:
        print('''Launching OpenConnect with {}, equivalent to:\n{}'''.format(args.exec, openconnect_command), file=stderr)
        with tempfile.TemporaryFile('w+') as tf:
            tf.write(cv)
            tf.flush()
            tf.seek(0)
            # redirect stdin from this file, before it is closed by the context manager
            # (it will remain accessible via the open file descriptor)
            dup2(tf.fileno(), 0)
        cmd = ["openconnect"] + openconnect_args
        if args.exec == 'pkexec':
            cmd = ["pkexec", "--user", "root"] + cmd
        elif args.exec == 'sudo':
            cmd = ["sudo"] + cmd
        execvp(cmd[0], cmd)

    else:
        varvals = {
            'HOST': quote('https://%s/%s' % (server, urlpath)),
            'USER': quote(un), 'COOKIE': quote(cv), 'OS': quote(args.ocos),
        }
        print('\n'.join('%s=%s' % pair for pair in varvals.items()))

if __name__ == "__main__":
    main()
