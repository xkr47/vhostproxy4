import io.vertx.ceylon.core.http {
    HttpServerRequest,
    HttpMethod,
    connect
}
import ceylon.collection {
    HashMap
}

[NextHop+] nextHops = [
NextHop { matchHost = "localhost:8080"; host = "localhost"; port = 8090; nextHost = "simpuraSsl"; pathPrefix = "/lolssl"; },
NextHop { matchHost = "localhost:8443"; host = "localhost"; port = 8090; nextHost = "simpura"; pathPrefix = "/lol"; }
];

Map<String, NextHop> nextHopMap = HashMap<String, NextHop>{ entries = { for(i in nextHops) if (i.enabled && i.accessGroups is Null) i.matchHost -> i }; };

"Resolve the next hop for this request. If no next hop found, the response must be taken care of and null returned."
NextHop? resolveNextHop(HttpServerRequest sreq) {
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
    if (!nextHop exists) {
        value sres = sreq.response();
        sres.setStatusCode(400);
        sres.setStatusMessage("No service defined for ``host``");
        sres.end();
    }
    return nextHop;
}
