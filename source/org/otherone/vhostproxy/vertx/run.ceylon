import io.vertx.ceylon.core { ... }
import io.vertx.ceylon.core.http { ... }
import io.vertx.ceylon.core.streams {
    ReadStream,
    WriteStream
}
//import io.vertx.core.http { HttpHeaders { ... } }
import ceylon.collection {
    HashSet,
    HashMap
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
import java.util.concurrent.locks {
    JReentrantLock = ReentrantLock
}
import io.vertx.ceylon.core.buffer {
    Buffer
}
import io.vertx.ceylon.core.net {
    JksOptions
}
import ceylon.file {
    parsePath,
    File
}

Logger log = logger(`package`);

class MyPump<T>(String type, ReadStream<T> readStream, WriteStream<T> writeStream) given T satisfies Buffer {
    void drainHandler() => readStream.resume();
    void dataHandler(T? data) {
        log.trace("``type`` (``data?.length() else 0`` bytes) '``data else "<null>"``'");
        writeStream.write(data);
        if (writeStream.writeQueueFull()) {
            readStream.pause();
            writeStream.drainHandler(drainHandler);
        }
    }
    shared void start() {
        readStream.handler(dataHandler);
    }
}

class ReentrantLock() satisfies Obtainable {
    JReentrantLock lock = JReentrantLock();
    shared actual void obtain() => lock.lockInterruptibly();
    shared actual void release(Throwable? error) => lock.unlock();
}

class ProxyService(HttpClient client) {
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

    class NextHop(
        shared String matchHost,
        shared String host,
        shared Integer port,
        shared Boolean enabled = true,
        shared Boolean forceHttps = false,
        shared String[]? accessGroups = null,
        shared String nextHost = host + ":" + port.string
    ) {}

    [NextHop+] nextHops = [
    NextHop { matchHost = "outerspace.dyndns.org:8443"; host = "localhost"; port = 8090; nextHost = "simpura"; }
    ];
    Map<String, NextHop> nextHopMap = HashMap<String, NextHop>{ entries = { for(i in nextHops) i.matchHost -> i }; };
    NextHop? resolveNextHop(String host) => nextHopMap.get(host);

    String dumpHeaders(MultiMap h) {
        value sb = StringBuilder();
        for (name in h.names()) {
            sb.append("\n\t").append(name).append(": ").append(h.getAll(name).reduce((String partial, String element) => partial + "\n\t  " + element) else "");
        }
        return sb.string;
    }

    String dumpCReq(HttpClientRequest req) => "\n\t" + req.method().name + " " + req.uri() + dumpHeaders(req.headers());
    String dumpSReq(HttpServerRequest req) => "\n\t" + req.method().name + " " + req.uri() + dumpHeaders(req.headers());
    String dumpCRes(HttpClientResponse res) => "\n\t" + res.statusCode().string + " " + res.statusMessage() + dumpHeaders(res.headers());
    String dumpSRes(HttpServerResponse res) => "\n\t" + res.getStatusCode().string + " " + res.getStatusMessage() + dumpHeaders(res.headers());

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

    shared void requestHandler(HttpServerRequest sreq) {
        value reqId = requestId.next();
        void fail(Integer code, String msg) {
            value sres = sreq.response();
            sres.exceptionHandler((Throwable t) {
                log.debug("``reqId`` Server response fail", t);
            });
            sres.setStatusCode(code);
            sres.setStatusMessage(msg);
            sres.end();
        }
        if (sreq.version() != http_1_1) {
            fail(505, "Only HTTP/1.1 supported");
            return;
        }
        value sreqh = sreq.headers();
        value origHost = sreqh.get("Host");
        if (! exists origHost) {
            fail(400, "Exhausted resources while trying to extract Host header from the request");
            return;
        }
        value nextHop = resolveNextHop(origHost);
        if (! exists nextHop) {
            fail(400, "Destination ``origHost`` unknown");
            return;
        }
        sreq.exceptionHandler((Throwable t) {
            log.debug("``reqId`` Server request fail", t);
            fail(500, t.message);
        });
        value chost = sreq.localAddress().host();
        log.debug("``reqId`` Incoming request from : ``chost``:``dumpSReq(sreq)``");
        value creq = client.request(sreq.method(), nextHop.port, nextHop.host, sreq.uri());
        creq.handler((HttpClientResponse cres) {
            log.debug("``reqId`` Incoming response ``dumpCRes(cres)``");
            cres.exceptionHandler((Throwable t) {
                log.debug("``reqId`` Client response fail", t);
                fail(500, t.message);
            });
            value sres = sreq.response();
            sres.exceptionHandler((Throwable t) {
                log.debug("``reqId`` Server response fail", t);
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

            value resPump = MyPump("Response body", cres, sres);
            cres.endHandler(() {
                log.debug("``reqId`` Response pumping complete");
                return sres.end();
            });
            resPump.start();
            log.debug("``reqId`` Response pumping started");
        });
        creq.exceptionHandler((Throwable t) {
            log.debug("``reqId`` Client request fail", t);
            fail(503, t.message);
        });
        value creqh = creq.headers();
        copyEndToEndHeaders(sreqh, creqh);
        creqh.set("Host", nextHop.nextHost);
        creqh.set("X-Host", origHost);
        creqh.set("X-Forwarded-For", chost);
        log.debug("``reqId`` Outgoing request to: ``nextHop.host``:``nextHop.port``:``dumpCReq(creq)``");
        value reqPump = MyPump("Request body", sreq, creq); // TODO dump contents
        sreq.endHandler(() {
            log.debug("``reqId`` Request pumping complete");
            return creq.end();
        });
        reqPump.start();
        log.debug("``reqId`` Request pumping started");
    }
}

"Run the module `org.otherone.vhostproxy`."
shared void run() {
    value baseport = 8080;

    addLogWriter(writeSimpleLog);
    defaultPriority = trace;
    log.info("Starting..");

    // TODO timeouts
    // TODO test responses without body e.g. 204

    value myVertx = vertx.vertx();
    value client = myVertx.createHttpClient(HttpClientOptions{
        connectTimeout = 10;
        idleTimeout = 30;
        maxPoolSize = 1000;
        maxWaitQueueSize = 20;
        tryUseCompression = false;
    });
    value proxyService = ProxyService(client);
    myVertx.createHttpServer(HttpServerOptions {
        compressionSupported = true;
        // handle100ContinueAutomatically = false;
        reuseAddress = true;
        idleTimeout = 5;
    }).requestHandler(proxyService.requestHandler).listen(baseport);
    log.info("HTTP Started on http://localhost:``baseport``/");
    String? keystorePassword;
    "Password file not found" assert (is File keystorePasswordFile = parsePath("keystore-password").resource);
    try (keystorePasswordFileReader = keystorePasswordFile.Reader("UTF-8")) {
        keystorePassword = keystorePasswordFileReader.readLine();
    }
    assert (exists keystorePassword);
    myVertx.createHttpServer(HttpServerOptions {
        compressionSupported = true;
        // handle100ContinueAutomatically = false;
        reuseAddress = true;
        idleTimeout = 5;
        ssl = true;
        keyStoreOptions = JksOptions { password = keystorePassword; path = "keystore"; };
    }).requestHandler(proxyService.requestHandler).listen(baseport - 80 + 443);
    log.info("HTTPS Started on https://localhost:``baseport - 80 + 443``/ . Startup complete.");
}
