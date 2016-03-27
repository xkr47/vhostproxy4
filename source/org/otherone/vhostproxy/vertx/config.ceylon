import ceylon.collection {
    HashMap,
    HashSet
}
import ceylon.file {
    parsePath,
    File
}
import ceylon.io.base64 {
    decode
}
import ceylon.io.buffer {
    newByteBufferWithData
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

Integer serverIdleTimeout = 60;

"A file containing 'group:commaSeparatedListOfIps'. Example: 'home:192.168.1.2,127.0.0.1'. IPv6 addresses also allowed in uncompressed format e.g. 0:0:0:0:0:0:0:1 for localhost."
String accessGroupFilename = "accessGroups.txt";

Boolean dumpRequestBody = true;
Boolean dumpResponseBody = false;

class NextHop (
    "When the hostname part of the 'Host' header matches, this entry will be used as next hop."
    shared String matchHost,
    "The hostname/ip of the next hop. Used by default in 'Host' header to next hop, can be overridden by setting `nextHost` explicitly.`"
    shared String host,
    "The port of the next hop. Used by default in 'Host' header to next hop, can be overridden by setting `nextHost` explicitly.`"
    shared Integer port,
    "If non-null, the value is prefixed to the path when constructing the request to the next hop."
    shared String? pathPrefix = null,
    "Use this to enable/disable the rule"
    shared Boolean enabled = true,
    "If true, users entering using HTTP will be redirected to the HTTPS service. If false the user can access the service both with HTTP and HTTPS."
    shared Boolean forceHttps = false,
    "If non-null, it's a list of access groups that are allowed to enter. Access groups are loaded from the file pointed to by `accessGroupFilename`."
    shared String[]? accessGroups = null,
    "The 'Host' header value to use in the request to the next hop."
    shared String nextHost = port == 80 then host else host + ":" + port.string,
    "If specified, the user is required to basic-authenticate, and will only be let in if the file has a matching 'username:password' line. Lines can be commented with '#'"
    shared String? passwordFile = null,
    "If true, propagate Authorization header to next hop. If passwordFile is null, Authorization header is always propagated."
    shared Boolean propagatePassword = false
) {}

"List of next hops which are chosen based on matchHost. These are just examples which forward requests to localhost:8090 with some additional adjustments."
[NextHop+] nextHops = [
NextHop { matchHost = "localhost"; host = "localhost"; port = 8090; nextHost = "simpura"; pathPrefix = "/lol"; /* accessGroups = [ "work", "home" ]; */ },
NextHop { matchHost = "publichost.example.com"; host = "localhost"; port = 8090; pathPrefix = "/lol2"; }
];

Map<String, NextHop> nextHopMap = HashMap<String, NextHop>{ entries = { for(i in nextHops) if (i.enabled) i.matchHost -> i }; };

Null reject(HttpServerRequest sreq, Integer status, String statusMsg) {
    value sres = sreq.response();
    sres.setStatusCode(status);
    sres.setStatusMessage(statusMsg);
    sres.end();
    return null;
}

String decodeBase64(String s) {
    return String(decode(newByteBufferWithData(*(s.map((ch) => ch.integer.byte)))).map((Byte b) => b.unsigned.character));
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
    if (exists groups = nextHop.accessGroups) {
        value groupSet = HashSet{ elements = groups; };
        variable value accessOk = false;
        if (is File file = parsePath(accessGroupFilename).resource) {
            try (reader = file.Reader()) {
                value clientHost = sreq.remoteAddress().host();
                while (exists line = reader.readLine()) {
                    if (exists colonLoc = line.firstOccurrence(':')) {
                        if (groupSet.contains(line[0:colonLoc])) {
                            if (line[colonLoc+1...].split(','.equals).contains(clientHost)) {
                                accessOk = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        if (!accessOk) {
            return reject(sreq, 403, "Forbidden");
        }
    }
    if (exists pf = nextHop.passwordFile) {
        variable value passwordOk = false;
        value authHeader = sreq.headers().get(Names.\iAUTHORIZATION);
        if (exists authHeader, authHeader.startsWith("Basic ")) {
            value userPass = decodeBase64(authHeader[6...]);
            if (is File file = parsePath(pf).resource) {
                try (reader = file.Reader()) {
                    while (exists line = reader.readLine()) {
                        if (line.trimmed.size >= 3, exists firstCh = line.first, firstCh != '#') {
                            if (userPass == line) {
                                passwordOk = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        if (!passwordOk) {
            value sres = sreq.response();
            sres.setStatusCode(401);
            sres.setStatusMessage("Authorization required for ``hostname``");
            sres.headers().add(Names.\iWWW_AUTHENTICATE, "Basic realm=\"``hostname``\"");
            sres.end();
            return null;
        }
        if (!nextHop.propagatePassword) {
            sreq.headers().remove(Names.\iAUTHORIZATION);
        }
    }
    value nextUri = if (exists prefix = nextHop.pathPrefix) then prefix + sreq.uri() else sreq.uri();
    value logBase = hostname;
    return Target(nextHop.host, nextHop.port, nextUri, nextHop.nextHost, logBase);
}
