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

class MyPump<T>(Anything(String, Throwable?=) trace, String type, ReadStream<T> readStream, WriteStream<T> writeStream, Anything()? firstBufferWrittenHandler = null) given T satisfies Buffer {
    void dataHandler(T? data) {
        trace("``type`` (``data?.length() else 0`` bytes) '``data else "<null>"``'");
        if (exists firstBufferWrittenHandler) { firstBufferWrittenHandler(); }
        writeStream.write(data);
        if (writeStream.writeQueueFull()) {
            readStream.pause();
            writeStream.drainHandler(readStream.resume);
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

shared class NextHop(
    shared String matchHost,
    shared String host,
    shared Integer port,
    shared String? pathPrefix = null,
    shared Boolean enabled = true,
    shared Boolean forceHttps = false,
    shared String[]? accessGroups = null,
    shared String nextHost = host + ":" + port.string
) {}

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
        void trace(String msg, Throwable? t = null) => log.trace("``reqId`` ``msg``", t);
        value chost = sreq.remoteAddress().host();
        trace("Incoming request from ``chost``:``dumpSReq(sreq)``");

        // NOTE: this handler is replaced later
        sreq.endHandler(() {
            trace("Incoming request complete");
        });
        value sres = sreq.response();
        sres.exceptionHandler((Throwable t) {
            trace("Outgoing response fail", t);
        });
        sres.headersEndHandler(() {
            trace("Outgoing response final ``dumpSRes(sres)``");
        });
        sres.bodyEndHandler(() {
            trace("Outgoing response complete");
        });

        void fail(Integer code, String msg) {
            sres.setStatusCode(code);
            sres.setStatusMessage(msg);
            sres.end();
        }
        sreq.exceptionHandler((Throwable t) {
            trace("Incoming request fail", t);
            fail(500, t.message);
        });
        if (sreq.version() != http_1_1) {
            fail(505, "Only HTTP/1.1 supported");
            return;
        }
        value nextHop = resolveNextHop(sreq);
        if (! exists nextHop) {
            // in this case the resolveNextHop takes care of sending the response
            return;
        }
        value sreqh = sreq.headers();
        value origHost = sreqh.get("Host");
        if (! exists origHost) {
            fail(400, "Exhausted resources while trying to extract Host header from the request");
            return;
        }
        value curi = if (exists prefix = nextHop.pathPrefix) then prefix + sreq.uri() else sreq.uri();
        value creq = client.request(sreq.method(), nextHop.port, nextHop.host, curi);
        creq.handler((HttpClientResponse cres) {
            trace("Incoming response ``dumpCRes(cres)``");
            cres.exceptionHandler((Throwable t) {
                trace("Incoming response fail", t);
                fail(500, t.message);
            });

            sres.setStatusCode(cres.statusCode());
            sres.setStatusMessage(cres.statusMessage());
            value headers = cres.headers();
            copyEndToEndHeaders(headers, sres.headers());
            if (!headers.contains(Names.\iCONTENT_LENGTH)) {
                sres.setChunked(true);
            }
            trace("Outgoing response initial ``dumpSRes(sres)``");

            value resPump = MyPump(trace, "Response body", cres, sres);
            cres.endHandler(() {
                trace("Incoming response complete");
                return sres.end();
            });
            resPump.start();
            trace("Incoming response body");
        });
        creq.exceptionHandler((Throwable t) {
            trace("Outgoing request fail", t);
            fail(503, t.message);
        });
        value creqh = creq.headers();
        copyEndToEndHeaders(sreqh, creqh);
        creqh.set("Host", nextHop.nextHost);
        creqh.set("X-Host", origHost);
        creqh.set("X-Forwarded-For", chost);
        value transferEncoding = sreqh.get(Names.\iTRANSFER_ENCODING);
        if (exists transferEncoding, transferEncoding.contains("chunked")) {
            creq.setChunked(true);
        }
        trace("Outgoing request (initial) to ``nextHop.host``:``nextHop.port``:``dumpCReq(creq)``");
        variable value finalRequestDumped = false;
        void dumpFinalRequest() {
            if (!finalRequestDumped) {
                finalRequestDumped = true;
                trace("Outgoing request final:``dumpCReq(creq)``");
            }
        }
        value reqPump = MyPump(trace, "Request body", sreq, creq, dumpFinalRequest); // TODO dump contents
        sreq.endHandler(() {
            creq.end();
            dumpFinalRequest();
            trace("Incoming request complete");
        });
        trace("Incoming request body");
        reqPump.start();
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
        idleTimeout = 120;
        maxPoolSize = 1000;
        maxWaitQueueSize = 20;
        tryUseCompression = false;
    });
    value proxyService = ProxyService(client);
    value serverIdleTimeout = 60;
    myVertx.createHttpServer(HttpServerOptions {
        compressionSupported = true;
        // handle100ContinueAutomatically = false;
        reuseAddress = true;
        idleTimeout = serverIdleTimeout;
    }).requestHandler(proxyService.requestHandler).listen(baseport);
    log.info("HTTP Started on http://localhost:``baseport``/");
    String? keystorePassword;
    "Password file not found" assert (is File keystorePasswordFile = parsePath("keystore-password").resource);
    try (keystorePasswordFileReader = keystorePasswordFile.Reader("UTF-8")) {
        keystorePassword = keystorePasswordFileReader.readLine();
    }
    "Password file was empty" assert (exists keystorePassword);
    myVertx.createHttpServer(HttpServerOptions {
        compressionSupported = true;
        // handle100ContinueAutomatically = false;
        reuseAddress = true;
        idleTimeout = serverIdleTimeout;
        ssl = true;
        keyStoreOptions = JksOptions { password = keystorePassword; path = "keystore"; };
    }).requestHandler(proxyService.requestHandler).listen(baseport - 80 + 443);
    log.info("HTTPS Started on https://localhost:``baseport - 80 + 443``/ . Startup complete.");
}
