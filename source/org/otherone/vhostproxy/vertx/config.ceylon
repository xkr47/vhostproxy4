import ceylon.collection {
    HashMap
}

import io.vertx.ceylon.core.http {
    HttpServerRequest,
    connect
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

[NextHop+] nextHops = [
NextHop { matchHost = "localhost:8080"; host = "localhost"; port = 8090; nextHost = "simpura"; pathPrefix = "/lol"; },
NextHop { matchHost = "localhost:8443"; host = "localhost"; port = 8090; nextHost = "simpuraSsl"; pathPrefix = "/lolssl"; }
];

Map<String, NextHop> nextHopMap = HashMap<String, NextHop>{ entries = { for(i in nextHops) if (i.enabled && i.accessGroups is Null) i.matchHost -> i }; };

"Resolve the next hop for this request. If no next hop found, the response must be taken care of and null returned."
Target? resolveNextHop(HttpServerRequest sreq, Boolean isTls) {
    if (sreq.method() == connect) {
        value sres = sreq.response();
        sres.setStatusCode(400); // TODO status code
        sres.setStatusMessage("Method not supported");
        sres.end();
        return null;
    }
    value host = sreq.headers().get("Host");
    if (! exists host) {
        value sres = sreq.response();
        sres.setStatusCode(400);
        sres.setStatusMessage("Exhausted resources while trying to extract Host header from the request");
        sres.end();
        return null;
    }
    value nextHop = nextHopMap.get(host);
    if (!exists nextHop) {
        value sres = sreq.response();
        sres.setStatusCode(400);
        sres.setStatusMessage("No service defined for ``host``");
        sres.end();
        return null;
    }
    value uri = if (exists prefix = nextHop.pathPrefix) then prefix + sreq.uri() else sreq.uri();
    value nextHost = nextHop.nextHost;
    value colonIdx = nextHost.firstIndexWhere((ch) => ch == ':');
    value logBase = if (exists colonIdx) then nextHost.initial(colonIdx) else nextHost;
    return Target(nextHop.host, nextHop.port, uri, nextHost, logBase);
}
