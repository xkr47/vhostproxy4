import ceylon.collection {
    HashMap
}

import io.netty.handler.codec.http {
    HttpHeaders {
        Names
    }
}
import io.vertx.ceylon.core.http {
    HttpServerRequest,
    connect,
    post,
    put,
    patch
}

shared object portConfig {
    "The HTTP port to listen to"
    shared Integer listenHttpPort = 8080;
    "The HTTPS port to listen to"
    shared Integer listenHttpsPort = 8443;
    "The HTTP port publicly visible. This can be different from `listenHttpPort` for example if you have some firewall rules set up to forward port 80 to e.g. 8080."
    shared Integer publicHttpPort = listenHttpPort;
    "The HTTPs port publicly visible. This can be different from `listenHttpsPort` for example if you have some firewall rules set up to forward port 443 to e.g. 8443."
    shared Integer publicHttpsPort = listenHttpsPort;
}

class NextHop (
    shared String matchHost,
    shared String host,
    shared Integer port,
    shared String? pathPrefix = null,
    shared Boolean enabled = true,
    shared Boolean forceHttps = false,
    shared String[]? accessGroups = null,
    shared String nextHost = port == 80 then host else host + ":" + port.string
) {}

"List of next hops which are chosen based on matchHost. These are just examples which forward requests to localhost:8090 with some additional adjustments."
[NextHop+] nextHops = [
NextHop { matchHost = "localhost"; host = "localhost"; port = 8090; nextHost = "simpura"; pathPrefix = "/lol"; },
NextHop { matchHost = "publichost.example.com"; host = "localhost"; port = 8090; pathPrefix = "/lol2"; }
];

Map<String, NextHop> nextHopMap = HashMap<String, NextHop>{ entries = { for(i in nextHops) if (i.enabled && i.accessGroups is Null) i.matchHost -> i }; };

Null reject(HttpServerRequest sreq, Integer status, String statusMsg) {
    value sres = sreq.response();
    sres.setStatusCode(status);
    sres.setStatusMessage(statusMsg);
    sres.end();
    return null;
}

String extractHosname(String hostHeader) {
    value lastIndex = hostHeader.lastIndex;
    if (!exists lastIndex) {
        return "";
    }
    for (i in lastIndex .. 0) {
        assert (exists ch = hostHeader[i]);
        if (!ch.digit) {
            if (ch == ':') {
                return hostHeader.initial(i);
            } else {
                break;
            }
        }
    }
    return hostHeader;
}

"Resolve the next hop for this request. If no next hop found, the response must be taken care of and null returned."
Target? resolveNextHop(HttpServerRequest sreq, Boolean isTls) {
    if (sreq.method() == connect) {
        return reject(sreq, 405, "Method not supported");
    }
    assert (exists uriFirstCharacter = sreq.uri().first);
    if (uriFirstCharacter != '/') {
        return reject(sreq, 400, "Proxy requests not supported");
    }
    value hostHeader = sreq.headers().get("Host");
    if (! exists hostHeader) {
        return reject(sreq, 400, "Exhausted resources while trying to extract Host header from the request");
    }
    value hostname = extractHosname(hostHeader);
    value nextHop = nextHopMap.get(hostname);
    if (!exists nextHop) {
        return reject(sreq, 404, "No service defined for ``hostHeader``");
    }
    if (nextHop.forceHttps && !isTls) {
        // require user to reload request with https
        value sres = sreq.response();
        value m = sreq.method();
        value nonRedirectableMethod = m == post || m == put || m == patch;
        // you should use 302 instead of 301 below if there is a chance you might need to disable forceHttps for some nextHop in the future
        sres.setStatusCode(nonRedirectableMethod then 405 else 301);
        sres.setStatusMessage("This host requires https");
        if (!nonRedirectableMethod) {
            value newHost =
                    (portConfig.publicHttpPort != 80 then hostname.initial(hostname.size - 1 - portConfig.publicHttpPort.string.size) else hostname) +
                    (portConfig.publicHttpsPort != 443 then ":" + portConfig.publicHttpsPort.string else "");
            sres.headers().add(Names.\iLOCATION, "https://" + newHost + sreq.uri());
        }
        sres.end();
        return null;
    }
    value nextUri = if (exists prefix = nextHop.pathPrefix) then prefix + sreq.uri() else sreq.uri();
    value logBase = hostname;
    return Target(nextHop.host, nextHop.port, nextUri, nextHop.nextHost, logBase);
}
