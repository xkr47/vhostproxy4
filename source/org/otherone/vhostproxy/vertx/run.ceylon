import io.vertx.ceylon.core { ... }
import io.vertx.ceylon.core.http { ... }
import io.vertx.ceylon.core.streams {
    pump
}
//import io.vertx.core.http { HttpHeaders { ... } }
import ceylon.collection {
    HashSet
}
import io.netty.handler.codec.http {
    HttpHeaders { Names, Values }
}
import ceylon.regex {
    regex,
    Regex
}
import ceylon.logging {
    logger,
    Logger,
    writeSimpleLog,
    addLogWriter,
    defaultPriority,
    trace
}
import io.vertx.core.http {
    CaseInsensitiveHeaders
}
import java.util.concurrent.locks {
    JReentrantLock = ReentrantLock
}

Logger log = logger(`package`);

Set<String> hopByHopHeaders = HashSet<String>{ elements = {
    Names.\iCONNECTION,
    "Keep-Alive",
    Names.\iPROXY_AUTHENTICATE,
    Names.\iPROXY_AUTHORIZATION,
    Names.\iTE,
    Names.\iTRAILER,
    Names.\iTRANSFER_ENCODING,
    Names.\iUPGRADE
};};

Regex connectionHeaderValueRE = regex("""\s*,[\s,]*+"""); // from RFC2616

void copyEndToEndHeaders(MultiMap from, MultiMap to) {
    to.addAll(from);
    for (name in hopByHopHeaders) {
        to.remove(name);
    }

    value connectionHeader = from.get(Names.\iCONNECTION);
    /*
    Set<String> requestHopByHopHeaders = if (exists connectionHeader)
    then HashSet<String>{ elements = connectionHeaderValueRE.split(connectionHeader.trimmed); }
    else emptySet;
    for (name in requestHopByHopHeaders) {
        to.remove(name);
    }
     */
    if (exists connectionHeader) {
        for (name in connectionHeaderValueRE.split(connectionHeader.trimmed)) {
            to.remove(name);
        }
    }
}

String dumpCReq(HttpClientRequest req) => "\n\t" + req.method().name + " " + req.uri() + dumpHeaders(req.headers());
String dumpSReq(HttpServerRequest req) => "\n\t" + req.method().name + " " + req.uri() + dumpHeaders(req.headers());
String dumpCRes(HttpClientResponse res) => "\n\t" + res.statusCode().string + " " + res.statusMessage() + dumpHeaders(res.headers());
String dumpSRes(HttpServerResponse res) => "\n\t" + res.getStatusCode().string + " " + res.getStatusMessage() + dumpHeaders(res.headers());

String dumpHeaders(MultiMap h) {
    value sb = StringBuilder();
    for (name in h.names()) {
        sb.append("\n\t").append(name).append(": ").append(h.getAll(name).reduce((String partial, String element) => partial + "\n\t  " + element) else "");
    }
    return sb.string;
}

class ReentrantLock() satisfies Obtainable {
    JReentrantLock lock = JReentrantLock();
    shared actual void obtain() => lock.lockInterruptibly();
    shared actual void release(Throwable? error) => lock.unlock();
}

object requestId {
    variable Integer prevRequestId = 0;
    value requestIdLock = ReentrantLock();
    shared Integer next() {
        value now = system.milliseconds;
        try (requestIdLock) {
            if (now <= prevRequestId) {
                return ++prevRequestId;
            } else {
                return prevRequestId = now;
            }
        }
    }
}

"Run the module `org.otherone.vhostproxy`."
shared void run() {
    addLogWriter(writeSimpleLog);
    defaultPriority = trace;
    log.info("Starting..");

/*
    MultiMap m = MultiMap(CaseInsensitiveHeaders());
    m.add("Kala", "first");
    m.add("Kala", "second");
    m.add("Kala", "third");
    log.info(m.getAll("Kala").string);
    log.info(m.names());
*/

    // TODO timeouts

    value myVertx = vertx.vertx();
    value client = myVertx.createHttpClient();
    myVertx.createHttpServer().requestHandler((HttpServerRequest sreq) {
        value reqId = requestId.next();
        void fail(Integer code, String msg) {
            value sres = sreq.response();
            sres.exceptionHandler((Throwable t) {
                log.debug("``reqId`` Server response fail");
                t.printStackTrace();
            });
            sres.setStatusCode(code);
            sres.setStatusMessage(msg);
            sres.end();
        }
        if (sreq.version() != http_1_1) {
            fail(505, "Only HTTP/1.1 supported");
            return;
        }
        value host = "localhost";
        value port = 8090;
        sreq.exceptionHandler((Throwable t) {
            log.debug("``reqId`` Server request fail");
            t.printStackTrace();
            fail(500, t.message);
        });
        value chost = sreq.localAddress().host();
        log.debug("``reqId`` Incoming request from : ``chost``:``dumpSReq(sreq)``");
        value creq = client.request(sreq.method(), port, host, sreq.uri());
        creq.handler((HttpClientResponse cres) {
            log.debug("``reqId`` Incoming response ``dumpCRes(cres)``");
            cres.exceptionHandler((Throwable t) {
                log.debug("``reqId`` Client response fail");
                t.printStackTrace();
                fail(500, t.message);
            });
            value sres = sreq.response();
            sres.exceptionHandler((Throwable t) {
                log.debug("``reqId`` Server response fail");
                t.printStackTrace();
                sres.end();
            });

            sres.setStatusCode(cres.statusCode());
            sres.setStatusMessage(cres.statusMessage());
            value headers = cres.headers();
            copyEndToEndHeaders(headers, sres.headers());
            if (!headers.contains(Names.\iCONTENT_LENGTH)) {
                sres.setChunked(true);
            }
            log.debug("``reqId`` Outgoing response1 ``dumpSRes(sres)``");
            sres.headersEndHandler(() {
                //headers.add(Names.\iTRANSFER_ENCODING, Values.\iCHUNKED);
                log.debug("``reqId`` Outgoing response2 ``dumpSRes(sres)``");
            });

            value resPump = pump.pump(cres, sres);
            cres.endHandler(() {
                log.debug("``reqId`` Response pumping complete");
                return sres.end();
            });
            resPump.start();
            log.debug("``reqId`` Response pumping started");
        });
        creq.exceptionHandler((Throwable t) {
            log.debug("``reqId`` Client request fail");
            t.printStackTrace();
            fail(503, t.message);
        });
        value sreqh = sreq.headers();
        value creqh = creq.headers();
        copyEndToEndHeaders(sreqh, creqh);
        if (exists origHost = sreqh.get("Host")) { creqh.set("X-Host", origHost); }
        creqh.set("Host", host + ":" + port.string);
        creqh.set("X-Forwarded-For", chost);
        log.debug("``reqId`` Outgoing request to: ``host``:``port``:``dumpCReq(creq)``");
        value reqPump = pump.pump(sreq, creq); // TODO dump contents
        sreq.endHandler(() {
            log.debug("``reqId`` Request pumping complete");
            return creq.end();
        });
        reqPump.start();
        log.debug("``reqId`` Request pumping started");
    }
    ).listen(8080);
    log.info("Started");
}
