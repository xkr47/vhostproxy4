import ceylon.collection {
    HashSet,
    HashMap,
    MutableMap
}
import ceylon.file {
    parsePath,
    File
}
import ceylon.logging {
    logger,
    Logger,
    writeSimpleLog,
    addLogWriter,
    defaultPriority,
    trace
}
import ceylon.regex {
    regex,
    Regex
}

import io.netty.handler.codec.http {
    HttpHeaders {
        Names // HttpHeaderNames is not deprecated but contains AsciiStrings instead :P
    }
}
import io.vertx.ceylon.core {
    ...
}
import io.vertx.ceylon.core.buffer {
    Buffer,
    buffer
}
import io.vertx.ceylon.core.file {
    AsyncFile,
    OpenOptions
}
import io.vertx.ceylon.core.http {
    ...
}
import io.vertx.ceylon.core.net {
    JksOptions
}
import io.vertx.ceylon.core.streams {
    ReadStream,
    WriteStream
}

Logger log = logger(`package`);

ReentrantLock logLock = ReentrantLock();

class MyPump<T>(AsyncFile logFile, String reqId, LogType logType, String type, ReadStream<T> readStream, WriteStream<T> writeStream, Boolean dumpBody, Anything()? firstBufferWrittenHandler = null) given T satisfies Buffer {
    void dataHandler(T? data) {
        writeStream.write(data);
        if (exists firstBufferWrittenHandler) { firstBufferWrittenHandler(); }

        try (logLock) {
            if (exists data) {
                logFile.write(buffer.buffer("``reqId`` ``logType.str`` ``system.milliseconds`` ``data.length()`` bytes``dumpBody then ":" else ""``\n", "UTF-8"));
                if (dumpBody) {
                    value prefix = "``reqId`` ``LogType.none.str`` ";
                    variable value start = 0;
                    for (i in 0:data.length()) {
                        if (data.getUnsignedByte(i) == '\n'.integer.byte) {
                            logFile.write(buffer.buffer(prefix, "UTF-8"));
                            logFile.write(data.slice(start, i + 1));
                            start = i+1;
                        }
                    }
                    logFile.write(buffer.buffer(prefix, "UTF-8"));
                    logFile.write(data.slice(start, data.length()));
                    logFile.write(buffer.buffer("\n", "UTF-8"));
                }
            } else {
                logFile.write(buffer.buffer("``reqId`` ``logType.str`` ``system.milliseconds``` null buffer\n", "UTF-8"));
            }
        }

        if (writeStream.writeQueueFull()) {
            readStream.pause();
            writeStream.drainHandler(tc0(readStream.resume));
        }
    }
    shared void start() {
        readStream.handler(tc(dataHandler));
    }
}

object logFiles {
    MutableMap<String, AsyncFile> logs = HashMap<String, AsyncFile>();
    shared AsyncFile get(String logBase, Vertx myVertx) {
        value log = logs.get(logBase);
        if (exists log) {
            return log;
        }
        value logFile = "logs/``logBase``";
        value log2 = myVertx.fileSystem().openBlocking(logFile, OpenOptions { create = true; read = false; write = true; truncateExisting = false; });
        value logProps = myVertx.fileSystem().propsBlocking(logFile);
        log2.setWritePos(logProps.size());
        log2.write(buffer.buffer("-----------------------------------------------------\n", "UTF-8"));
        logs.put(logBase, log2);
        return log2;
    }
}

class Target (
    shared String socketHost,
    shared Integer socketPort,
    shared String uri,
    shared String hostHeader,
    shared String logBase
){}

class LogType of sreq | creq | cres | sres | reqbody | resbody | none {
    shared String str;
    shared new sreq { str = ">| "; }
    shared new creq { str = " |>"; }
    shared new cres { str = " |<"; }
    shared new sres { str = "<| "; }
    shared new reqbody { str = ">>>"; }
    shared new resbody { str = "<<<"; }
    shared new none { str = "   "; }
    assert(str.size == 3);
}

shared class RejectReason of incomingRequestFail | outgoingRequestFail | incomingResponseFail | noHostHeader {
    shared new incomingRequestFail {}
    shared new outgoingRequestFail {}
    shared new incomingResponseFail {}
    shared new noHostHeader {}
}

class ProxyService(HttpClient client, Boolean isTls, Vertx myVertx) {
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

    value keepAliveHeaderValue = "timeout=``serverIdleTimeout``";

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

    String dumpHeaders(MultiMap h, String indent) {
        value sb = StringBuilder();
        for (name in h.names()) {
            sb.append("\n").append(indent).append(name).append(": ").append(h.getAll(name).reduce((String partial, String element) => partial + "\n" + indent + "  " + element) else "");
        }
        return sb.string;
    }

    String dumpCReq(HttpClientRequest req) => "\n" + req.method().name + " " + req.uri() + dumpHeaders(req.headers(), "");
    String dumpSReq(HttpServerRequest req, String indent) => "\n" + indent + req.method().name + " " + req.uri() + " " + req.version().name + dumpHeaders(req.headers(), indent);
    String dumpCRes(HttpClientResponse res) => "\n" + res.statusCode().string + " " + res.statusMessage() + dumpHeaders(res.headers(), "");
    String dumpSRes(HttpServerResponse res, String indent) => "\n" + indent + res.getStatusCode().string + " " + res.getStatusMessage() + dumpHeaders(res.headers(), indent);

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
/*
    abstract class LogType(shared String str) of ltSreq | ltCreq | ltCres | ltSres | ltReqbody | ltResbody {}
    object ltSreq extends LogType(">| ") {}
    */

    shared void requestHandler(HttpServerRequest sreq) {
        value reqId = requestId.next().string;
        variable AsyncFile? logFile = null;
        void trace(LogType logType, String msg, Throwable? t = null) {
            if (exists f = logFile) {
                value infix = "\n" + reqId + " " + LogType.none.str + " ";
                try (logLock) {
                    f.write(buffer.buffer(reqId + " " + logType.str + " " + system.milliseconds.string + " " + msg.split((ch) => ch == '\n').reduce((String a,n) => a + infix+ n) + "\n", "UTF-8"));
                }
            } else {
                log.trace("``reqId`` ``msg``", t);
            }
        }
        value chost = sreq.remoteAddress().host();
        value reqLogInfix = "Incoming ``isTls then "HTTPS " else ""``request from ``chost``:";
        log.trace("``reqId`` ``reqLogInfix````dumpSReq(sreq, "\t")``");

        // NOTE: this handler is replaced later
        sreq.endHandler(() {
            trace(LogType.sreq, "Incoming request complete");
        });
        value sres = sreq.response();
        sres.headers().add("Keep-Alive", keepAliveHeaderValue);
        sres.headers().add(Names.\iCONNECTION, "keep-alive");
        sres.exceptionHandler((Throwable t) {
            trace(LogType.sres, "Outgoing response fail", t);
        });
        sres.headersEndHandler(() {
            trace(LogType.sres, "Outgoing response final ``dumpSRes(sres, logFile exists then "" else "\t")``");
        });
        sres.bodyEndHandler(() {
            trace(LogType.sres, "Outgoing response complete");
        });
        sreq.exceptionHandler(tc((Throwable t) {
            trace(LogType.sreq, "Incoming request fail", t);
            fail(sreq, 500, RejectReason.incomingRequestFail, t.message);
        }));
/*        if (sreq.version() != http_1_1) {
            fail(505, "Only HTTP/1.1 supported");
            return;
        }*/
        value nextHop = resolveNextHop(sreq, isTls);
        if (! exists nextHop) {
            // in this case the resolveNextHop takes care of sending the response
            return;
        }
        value logFile2 = logFile = logFiles.get(nextHop.logBase, myVertx);
        trace(LogType.sreq, "``reqLogInfix````dumpSReq(sreq, "")``");

        value sreqh = sreq.headers();
        value origHost = sreqh.get("Host");
        if (! exists origHost) {
            fail(sreq, 400, RejectReason.noHostHeader);
            return;
        }
        value creq = client.request(sreq.method(), nextHop.socketPort, nextHop.socketHost, nextHop.uri);
        creq.handler(tc((HttpClientResponse cres) {
            trace(LogType.cres, "Incoming response ``dumpCRes(cres)``");
            cres.exceptionHandler((Throwable t) {
                trace(LogType.cres, "Incoming response fail", t);
                fail(sreq, 502, RejectReason.incomingResponseFail, t.message);
            });

            sres.setStatusCode(cres.statusCode());
            sres.setStatusMessage(cres.statusMessage());
            value headers = cres.headers();
            copyEndToEndHeaders(headers, sres.headers());
            sres.headers().add("Keep-Alive", keepAliveHeaderValue);
            sres.headers().add(Names.\iCONNECTION, "keep-alive");
            if (!headers.contains(Names.\iCONTENT_LENGTH)) {
                sres.setChunked(true);
            }
            trace(LogType.sres, "Outgoing response initial ``dumpSRes(sres, "")``");

            value resPump = MyPump(logFile2, reqId, LogType.resbody, "Response body", cres, sres, dumpResponseBody);
            cres.endHandler(tc0(() {
                trace(LogType.cres, "Incoming response complete");
                return sres.end();
            }));
            resPump.start();
            trace(LogType.resbody, "Incoming response body");
        }));
        creq.exceptionHandler(tc((Throwable t) {
            trace(LogType.creq, "Outgoing request fail", t);
            value msg = t.message.startsWith("connection timed out:") then "connection timed out" else t.message;
            fail(sreq, 502, RejectReason.outgoingRequestFail, msg);
        }));
        value creqh = creq.headers();
        copyEndToEndHeaders(sreqh, creqh);
        creqh.set("Host", nextHop.hostHeader);
        creqh.set("X-Host", origHost);
        creqh.set("X-Forwarded-For", chost);
        creqh.set("X-Forwarded-Proto", isTls then "https" else "http");
        value transferEncoding = sreqh.get(Names.\iTRANSFER_ENCODING);
        if (exists transferEncoding, transferEncoding.contains("chunked")) {
            creq.setChunked(true);
        }
        trace(LogType.creq, "Outgoing request (initial) to ``nextHop.socketHost``:``nextHop.socketPort``:``dumpCReq(creq)``");
        variable value finalRequestDumped = false;
        void dumpFinalRequest() {
            if (!finalRequestDumped) {
                finalRequestDumped = true;
                trace(LogType.creq, "Outgoing request final:``dumpCReq(creq)``");
            }
        }
        value reqPump = MyPump(logFile2, reqId, LogType.reqbody, "Request body", sreq, creq, dumpRequestBody, dumpFinalRequest);
        sreq.endHandler(tc0(() {
            creq.end();
            dumpFinalRequest();
            trace(LogType.sreq, "Incoming request complete");
        }));
        trace(LogType.reqbody, "Incoming request body");
        reqPump.start();
    }
}

"Run the module `org.otherone.vhostproxy`."
shared void run() {
    addLogWriter(writeSimpleLog);
    defaultPriority = trace;
    log.info("Starting..");

    // TODO timeouts
    // TODO test responses without body e.g. 204
    value myVertx = vertx.vertx();
    value verticle = MyVerticle();
    verticle.deploy(myVertx, null, (String|Throwable res) {
        if (is String res) {
            log.info("Verticle deployed, deployment id is: ``res``");
        } else {
            log.error("Verticle deployment failed!", res);
        }
    });
}

shared class MyVerticle() extends Verticle() {
    shared actual void start() {
        log.info("Verticle starting..");

        value client = vertx.createHttpClient(HttpClientOptions{
            connectTimeout = 10;
            idleTimeout = 120;
            maxPoolSize = 1000;
            maxWaitQueueSize = 20;
            tryUseCompression = false;
        });
        vertx.createHttpServer(HttpServerOptions {
            compressionSupported = true;
            // handle100ContinueAutomatically = false;
            reuseAddress = true;
            idleTimeout = serverIdleTimeout;
        }).requestHandler(tc(ProxyService(client, false, vertx).requestHandler)).listen(portConfig.listenHttpPort, (HttpServer|Throwable res) {
            if (is HttpServer res) {
                log.info("HTTP Started on port ``portConfig.listenHttpPort``, sample public url: http://localhost:``portConfig.publicHttpPort``/");
            } else {
                log.error("HTTP failed on port ``portConfig.listenHttpPort``", res);
            }
        });
        String? keystorePassword;
        "Password file not found" assert (is File keystorePasswordFile = parsePath("keystore-password").resource);
        try (keystorePasswordFileReader = keystorePasswordFile.Reader("UTF-8")) {
            keystorePassword = keystorePasswordFileReader.readLine();
        }
        "Password file was empty" assert (exists keystorePassword);
        vertx.createHttpServer(HttpServerOptions {
            compressionSupported = true;
            // handle100ContinueAutomatically = false;
            reuseAddress = true;
            idleTimeout = serverIdleTimeout;
            ssl = true;
            keyStoreOptions = JksOptions { password = keystorePassword; path = "keystore"; };
        }).requestHandler(tc(ProxyService(client, true, vertx).requestHandler)).listen(portConfig.listenHttpsPort, (HttpServer|Throwable res) {
            if (is HttpServer res) {
                log.info("HTTPS Started on port ``portConfig.listenHttpsPort``, sample public url: https://localhost:``portConfig.publicHttpsPort``/ .");
            } else {
                log.error("HTTPS failed on port ``portConfig.listenHttpPort``", res);
            }
        });
        log.info("Startup initialized.");
    }
}
