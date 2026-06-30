import os
import re
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from mitmproxy import ctx, http


LOCAL_ORIGIN = os.environ.get(
    "GB_MITM_LOCAL_ORIGIN",
    "https://localhost:1337",
).rstrip("/")

UPSTREAMS = {
    "s4": os.environ.get("GB_MITM_S4_UPSTREAM", "https://s4.example.invalid/"),
    "idp": os.environ.get("GB_MITM_IDP_UPSTREAM", "https://ias-cloud.example.invalid/"),
    "idp_od": os.environ.get("GB_MITM_IDP_OD_UPSTREAM", "https://ias-ondemand.example.invalid/"),
}

LISTEN_PORT = int(os.environ.get("GB_MITM_LISTEN_PORT", "1337"))
LOCAL_HOSTNAMES = {
    item.strip()
    for item in os.environ.get("GB_MITM_LOCAL_HOSTNAMES", "localhost,127.0.0.1").split(",")
    if item.strip()
}
LOCAL_ORIGIN_CANDIDATES = {LOCAL_ORIGIN} | {
    f"https://{hostname}:{LISTEN_PORT}" for hostname in LOCAL_HOSTNAMES
}

UPSTREAM_HOSTS = {upstream_host for upstream_host in (urlparse(url).netloc for url in UPSTREAMS.values())}
LOCAL_HOSTS = {
    urlparse(origin).netloc
    for origin in LOCAL_ORIGIN_CANDIDATES
}


def normalize_netloc(netloc):
    if not netloc:
        return ""
    value = netloc.strip().lower()
    if value.endswith(":443"):
        return value[:-4]
    return value

HOP_BY_HOP_HEADERS = {
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

BLOCKED_RESPONSE_HEADERS = HOP_BY_HOP_HEADERS | {
    "content-length",
    "content-encoding",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "strict-transport-security",
}

REWRITE_CONTENT_TYPES = (
    "text/html",
    "application/javascript",
    "text/javascript",
    "application/json",
    "text/css",
    "application/xml",
    "text/xml",
)

ALLOWED_METHODS = "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"
DEFAULT_ALLOWED_HEADERS = (
    "Authorization, Content-Type, X-CSRF-Token, X-Requested-With, Accept, Origin"
)


@dataclass
class Route:
    name: str
    upstream_path: str


def upstream_host(upstream):
    return urlparse(upstream).netloc


def upstream_hostname(upstream):
    return urlparse(upstream).hostname or ""


def upstream_origin(upstream):
    parsed = urlparse(upstream)
    return f"{parsed.scheme}://{parsed.netloc}"


def local_origin(flow=None):
    if flow is None:
        return LOCAL_ORIGIN

    host = flow.request.headers.get("Host", "").strip()
    normalized_host = normalize_netloc(host)
    normalized_local_hosts = {normalize_netloc(local_host) for local_host in LOCAL_HOSTS}
    normalized_upstream_hosts = {normalize_netloc(upstream_host) for upstream_host in UPSTREAM_HOSTS}

    if normalized_host in normalized_local_hosts:
        return f"https://{host}".rstrip("/")

    # In mitmproxy reverse mode the flow host/Host header can already be the
    # upstream S4 host. Flask's request.host_url never sees that value: it sees
    # the local proxy origin opened by the browser. Prefer the client SNI when
    # it identifies one of our local proxy hostnames.
    sni = getattr(flow.client_conn, "sni", None)
    if sni:
        sni_host = sni.strip()
        if sni_host in LOCAL_HOSTNAMES:
            return f"https://{sni_host}:{LISTEN_PORT}"

    if normalized_host in normalized_upstream_hosts:
        return LOCAL_ORIGIN

    if host:
        return f"https://{host}".rstrip("/")

    return LOCAL_ORIGIN


def local_prefix(name, origin):
    return f"{origin}/{name}"


def escaped_https(value):
    return value.replace("https://", "https:\\/\\/")


def rewrite_absolute_url(value, origin):
    if not value:
        return value

    rewritten = value
    for name, upstream in UPSTREAMS.items():
        host = upstream_host(upstream)
        base = upstream.rstrip("/")
        prefix = local_prefix(name, origin)

        rewritten = rewritten.replace(base, prefix)
        rewritten = rewritten.replace(f"https://{host}", prefix)
        rewritten = rewritten.replace(f"http://{host}", prefix)
        rewritten = rewritten.replace(f"https:\\/\\/{host}", escaped_https(prefix))
        rewritten = rewritten.replace(f"http:\\/\\/{host}", escaped_https(prefix))

    return rewritten


def rewrite_local_url_to_upstream(value, current_name, origin):
    if not value:
        return value

    rewritten = value
    for name, upstream in UPSTREAMS.items():
        for origin_candidate in LOCAL_ORIGIN_CANDIDATES | {origin}:
            prefix = local_prefix(name, origin_candidate)
            upstream_base = upstream.rstrip("/")
            rewritten = rewritten.replace(prefix, upstream_base)
            rewritten = rewritten.replace(escaped_https(prefix), escaped_https(upstream_base))

    if rewritten in LOCAL_ORIGIN_CANDIDATES | {origin}:
        rewritten = upstream_origin(UPSTREAMS[current_name])

    return rewritten


def rewrite_location(value, current_name, origin):
    if not value:
        return value

    value = rewrite_absolute_url(value, origin)
    if value.startswith("/"):
        return local_prefix(current_name, origin) + value

    return value


def normalize_path_for_upstream(name, path):
    if name != "idp":
        return path

    idp_od_host = upstream_host(UPSTREAMS["idp_od"])
    local_hosts = [urlparse(origin).netloc for origin in LOCAL_ORIGIN_CANDIDATES]
    for local_host in local_hosts:
        path = path.replace(
            f"{local_host}/idp_od",
            idp_od_host,
        )
        path = path.replace(
            f"{local_host.replace(':', '%3A')}/idp_od",
            idp_od_host,
        )
        path = path.replace(
            f"{local_host.replace(':', '%3a')}/idp_od",
            idp_od_host,
        )
    return path


def route_for_path(raw_path):
    path = raw_path.split("?", 1)[0]
    query = ""
    if "?" in raw_path:
        query = "?" + raw_path.split("?", 1)[1]

    if path in {"", "/"}:
        return None

    aliases = (
        ("/saml2/", "idp", "saml2/"),
        ("/oauth/", "idp", "oauth/"),
        ("/login/", "idp", "login/"),
        ("/universalui/", "idp", "universalui/"),
    )
    for prefix, name, upstream_prefix in aliases:
        if path.startswith(prefix):
            return Route(name, upstream_prefix + path[len(prefix):] + query)

    if path == "/ui" or path.startswith("/ui/"):
        suffix = path[4:] if path.startswith("/ui/") else ""
        return Route("s4", ("ui/" + suffix if suffix else "ui") + query)

    match = re.match(r"^/sap\(([^)]*)\)(?:/(.*))?$", path)
    if match:
        session_part = match.group(1)
        suffix = match.group(2) or ""
        upstream_path = f"sap({session_part})"
        if suffix:
            upstream_path += f"/{suffix}"
        return Route("s4", upstream_path + query)

    if path == "/sap" or path.startswith("/sap/"):
        suffix = path[5:] if path.startswith("/sap/") else ""
        return Route("s4", ("sap/" + suffix if suffix else "sap") + query)

    parts = path.lstrip("/").split("/", 1)
    name = parts[0]
    if name in UPSTREAMS:
        suffix = parts[1] if len(parts) > 1 else ""
        return Route(name, suffix + query)

    return None


def cors_headers(flow):
    return {
        "Access-Control-Allow-Origin": flow.request.headers.get("Origin", LOCAL_ORIGIN),
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": ALLOWED_METHODS,
        "Access-Control-Allow-Headers": flow.request.headers.get(
            "Access-Control-Request-Headers",
            DEFAULT_ALLOWED_HEADERS,
        ),
    }


def preflight_response(flow):
    headers = cors_headers(flow)
    headers["Access-Control-Max-Age"] = "86400"
    return http.Response.make(204, b"", headers)


def clear_session_response(flow):
    target = "/s4/ui?_gb_clear=1&_=" + str(int(time.time() * 1000)) + "#Shell-home"
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<title>SAP Startup</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:28px;color:#333}} .box{{max-width:720px}}</style>
</head>
<body>
<div class="box">Clearing the local session. Opening SAP...</div>
<script>
(function(){{
  try {{ localStorage.clear(); }} catch(e) {{}}
  try {{ sessionStorage.clear(); }} catch(e) {{}}
  try {{
    var paths=['/','/s4','/s4/','/idp','/idp/','/idp_od','/idp_od/','/sap','/sap/','/ui','/ui/','/saml2','/saml2/','/oauth','/oauth/','/login','/login/','/universalui','/universalui/'];
    document.cookie.split(';').forEach(function(c){{
      var name=c.split('=')[0].trim();
      if(!name) return;
      paths.forEach(function(p){{
        document.cookie=name+'=; Max-Age=0; expires=Thu, 01 Jan 1970 00:00:00 GMT; path='+p+'; SameSite=None; Secure';
        document.cookie=name+'=; Max-Age=0; expires=Thu, 01 Jan 1970 00:00:00 GMT; path='+p+'; Secure';
      }});
    }});
  }} catch(e) {{}}
  setTimeout(function(){{ window.location.replace('{target}'); }}, 150);
}})();
</script>
<noscript><a href="{target}">Open SAP</a></noscript>
</body>
</html>"""

    response = http.Response.make(
        200,
        html.encode("utf-8"),
        {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
            "Clear-Site-Data": '"cache", "cookies", "storage", "executionContexts"',
        },
    )

    cookie_names = set()
    cookie_header = flow.request.headers.get("Cookie", "")
    for cookie_part in cookie_header.split(";"):
        cookie_name = cookie_part.split("=", 1)[0].strip()
        if cookie_name:
            cookie_names.add(cookie_name)

    cookie_names.update(
        [
            "JSESSIONID",
            "XSRF-TOKEN",
            "sap-usercontext",
            "sap-contextid",
            "MYSAPSSO2",
            "SAP_SESSIONID",
            "ias.location",
            "login-token",
            "xsuaa-session",
            "OAuth_Token_Request_State",
            "SAMLRequest",
            "SAMLResponse",
        ]
    )
    paths = [
        "/",
        "/s4",
        "/s4/",
        "/idp",
        "/idp/",
        "/idp_od",
        "/idp_od/",
        "/sap",
        "/sap/",
        "/ui",
        "/ui/",
        "/saml2",
        "/saml2/",
        "/oauth",
        "/oauth/",
        "/login",
        "/login/",
        "/universalui",
        "/universalui/",
    ]
    for cookie_name in cookie_names:
        for path in paths:
            response.headers.add(
                "Set-Cookie",
                f"{cookie_name}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path={path}; SameSite=None; Secure",
            )
            response.headers.add(
                "Set-Cookie",
                f"{cookie_name}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path={path}; Secure",
            )

    return response


def rewrite_set_cookie(value, current_name):
    if not value:
        return value

    for upstream in UPSTREAMS.values():
        host = upstream_host(upstream)
        value = value.replace(f"Domain={host};", "")
        value = value.replace(f"Domain=.{host};", "")
        value = value.replace(f"domain={host};", "")
        value = value.replace(f"domain=.{host};", "")

    prefix = f"/{current_name}"
    path_rewrites = [
        ("Path=/saml2", f"Path={prefix}/saml2"),
        ("path=/saml2", f"path={prefix}/saml2"),
        ("Path=/oauth", f"Path={prefix}/oauth"),
        ("path=/oauth", f"path={prefix}/oauth"),
        ("Path=/login", f"Path={prefix}/login"),
        ("path=/login", f"path={prefix}/login"),
    ]
    for old, new in path_rewrites:
        value = value.replace(old, new)

    return value


def rewrite_body(content, content_type, origin):
    if not content:
        return content

    ct = (content_type or "").lower()
    if not any(item in ct for item in REWRITE_CONTENT_TYPES):
        return content

    try:
        text = content.decode("utf-8", errors="ignore")
        text = rewrite_absolute_url(text, origin)

        local_host = urlparse(origin).netloc
        origin_escaped = escaped_https(origin)
        idp_host = upstream_host(UPSTREAMS["idp"])
        idp_od_host = upstream_host(UPSTREAMS["idp_od"])

        text = text.replace(
            f"{idp_host}/saml2/idp/sso/{idp_od_host}",
            f"{local_host}/idp/saml2/idp/sso/{idp_od_host}",
        )
        text = text.replace(
            f"https://{idp_host}",
            f"{origin}/idp",
        )
        text = text.replace(
            f"https://{idp_od_host}",
            f"{origin}/idp_od",
        )
        text = text.replace(
            f"https:\\/\\/{idp_host}",
            f"{origin_escaped}\\/idp",
        )
        text = text.replace(
            f"https:\\/\\/{idp_od_host}",
            f"{origin_escaped}\\/idp_od",
        )

        for root_path in ["saml2", "oauth", "login"]:
            text = text.replace(f'action="/{root_path}/', f'action="/idp/{root_path}/')
            text = text.replace(f"action='/{root_path}/", f"action='/idp/{root_path}/")
            text = text.replace(f'href="/{root_path}/', f'href="/idp/{root_path}/')
            text = text.replace(f"href='/{root_path}/", f"href='/idp/{root_path}/")
            text = text.replace(f'src="/{root_path}/', f'src="/idp/{root_path}/')
            text = text.replace(f"src='/{root_path}/", f"src='/idp/{root_path}/")

        text = text.replace('action="/ui"', 'action="/s4/ui"')
        text = text.replace("action='/ui'", "action='/s4/ui'")
        text = text.replace('action="/ui/"', 'action="/s4/ui/"')
        text = text.replace("action='/ui/'", "action='/s4/ui/'")
        text = text.replace('href="/ui/', 'href="/s4/ui/')
        text = text.replace("href='/ui/", "href='/s4/ui/")
        text = text.replace('src="/ui/', 'src="/s4/ui/')
        text = text.replace("src='/ui/", "src='/s4/ui/")

        for attr in ["href", "src", "action"]:
            text = text.replace(f'{attr}="/sap/', f'{attr}="/s4/sap/')
            text = text.replace(f"{attr}='/sap/", f"{attr}='/s4/sap/")
            text = text.replace(f'{attr}="/sap(', f'{attr}="/s4/sap(')
            text = text.replace(f"{attr}='/sap(", f"{attr}='/s4/sap(")

        text = text.replace('url("/sap/', 'url("/s4/sap/')
        text = text.replace("url('/sap/", "url('/s4/sap/")
        text = text.replace('"/sap/', '"/s4/sap/')
        text = text.replace("'/sap/", "'/s4/sap/")
        text = text.replace('"/sap(', '"/s4/sap(')
        text = text.replace("'/sap(", "'/s4/sap(")

        return text.encode("utf-8")

    except Exception as exc:
        ctx.log.warn(f"Body rewrite failed: {exc}")
        return content


class SAPReverseProxy:
    def request(self, flow: http.HTTPFlow):
        origin = local_origin(flow)
        path = flow.request.path or "/"
        flow.metadata["gb_local_origin"] = origin

        if path.split("?", 1)[0] in {"", "/"}:
            flow.response = clear_session_response(flow)
            return

        if path.split("?", 1)[0] in {"/clear-session", "/fresh-login"}:
            flow.response = clear_session_response(flow)
            return

        if path.split("?", 1)[0] == "/favicon.ico":
            flow.response = http.Response.make(204, b"", {})
            return

        route = route_for_path(path)
        if route is None:
            flow.response = http.Response.make(
                404,
                f"Unknown upstream route: {path.lstrip('/').split('/', 1)[0]}".encode("utf-8"),
                {"Content-Type": "text/plain; charset=utf-8"},
            )
            return

        flow.metadata["gb_upstream_name"] = route.name
        upstream = UPSTREAMS[route.name]
        upstream_parsed = urlparse(upstream)
        upstream_path = normalize_path_for_upstream(route.name, route.upstream_path)

        if flow.request.method.upper() == "OPTIONS":
            flow.response = preflight_response(flow)
            return

        headers = flow.request.headers
        for key in list(headers.keys()):
            lower_key = key.lower()
            if lower_key in HOP_BY_HOP_HEADERS:
                del headers[key]
                continue
            if lower_key in {"origin", "referer"}:
                headers[key] = rewrite_local_url_to_upstream(headers[key], route.name, origin)

        headers["Host"] = upstream_parsed.netloc
        headers["Accept-Encoding"] = "identity"
        if "User-Agent" not in headers:
            headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        if "Accept" not in headers:
            headers["Accept"] = "*/*"
        if "Accept-Language" not in headers:
            headers["Accept-Language"] = "it-IT,it;q=0.9,en;q=0.8"

        flow.request.scheme = upstream_parsed.scheme
        flow.request.host = upstream_parsed.hostname
        flow.request.port = upstream_parsed.port or 443
        flow.request.path = "/" + upstream_path.lstrip("/")
        flow.request.http_version = "HTTP/1.1"

        ctx.log.info(
            f"{flow.request.method} {path} -> {flow.request.scheme}://{headers['Host']}{flow.request.path}"
        )

    def response(self, flow: http.HTTPFlow):
        current_name = flow.metadata.get("gb_upstream_name")
        if not current_name or flow.response is None:
            return

        origin = flow.metadata.get("gb_local_origin", LOCAL_ORIGIN)
        headers = flow.response.headers

        set_cookies = headers.get_all("Set-Cookie")
        location = headers.get("Location")

        for key in list(headers.keys()):
            if key.lower() in BLOCKED_RESPONSE_HEADERS or key.lower() == "set-cookie":
                del headers[key]

        if location:
            headers["Location"] = rewrite_location(location, current_name, origin)

        for cookie in set_cookies:
            headers.add("Set-Cookie", rewrite_set_cookie(cookie, current_name))

        for key, value in cors_headers(flow).items():
            headers[key] = value
        headers["Access-Control-Expose-Headers"] = "Location, Set-Cookie, X-CSRF-Token"
        headers["Vary"] = "Origin"

        content_type = headers.get("Content-Type", "")
        if flow.response.raw_content is None:
            return

        rewritten = rewrite_body(flow.response.raw_content, content_type, origin)
        if rewritten != flow.response.raw_content:
            flow.response.raw_content = rewritten


addons = [SAPReverseProxy()]
