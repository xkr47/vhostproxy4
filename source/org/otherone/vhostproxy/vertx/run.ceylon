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
    trace,
    Priority,
    Category,
    info,
    debug,
    warn,
    error,
    fatal
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
import io.vertx.core {
    ...
}
import io.vertx.core.buffer {
    Buffer
}
import io.vertx.core.file {
    AsyncFile,
    OpenOptions
}
import io.vertx.core.http {
    ...
}
import io.vertx.core.net {
    JksOptions
}
import io.vertx.core.streams {
    ReadStream,
    WriteStream
}
import io.vertx.ext.web {
    Router,
    RoutingContext
}
import io.vertx.core.json {
    JsonObject
}
import io.nitor.api.backend.proxy {
    ...
}
/*
import org.apache.logging.log4j.core.config.plugins.validation.constraints {
    required
}
*/
import java.util.\ifunction {
    Supplier
}
import java.lang {
    JString = String,
    System
}
import org.apache.logging.log4j {
    LogManager,
    Level,
    Log4jLogger = Logger,
    Marker,
    MarkerManager
}
import io.vertx.core.logging {
    LoggerFactory
}
import ceylon.interop.java {
    javaClass
}

Logger log = logger(`package`);
/*
ReentrantLock logLock = ReentrantLock();

class MyPump<T>(AsyncFile logFile, String reqId, LogType logType, String type, ReadStream<T> readStream, WriteStream<T> writeStream, Boolean dumpBody, Anything()? firstBufferWrittenHandler = null) given T satisfies Buffer {
    void dataHandler(T data) {
        writeStream.write(data);
        if (exists firstBufferWrittenHandler) { firstBufferWrittenHandler(); }

        try (logLock) {
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
*/
class Target (
    shared String socketHost,
    shared Integer socketPort,
    shared String uri,
    shared String hostHeader,
    shared String logBase
){}
/*
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
*/
shared class RejectReason of incomingRequestFail | outgoingRequestFail | incomingResponseFail | noHostHeader {
    shared new incomingRequestFail {}
    shared new outgoingRequestFail {}
    shared new incomingResponseFail {}
    shared new noHostHeader {}
}

class MyLogProxyTracer() extends SimpleLogProxyTracer() {

    variable String? first = null;
    variable Marker? marker = null;
    Log4jLogger logger = LogManager.getLogger(javaClass<MyLogProxyTracer>());

    shared actual void incomingRequestStart(RoutingContext ctx, Boolean isTls, Boolean isHTTP2, String chost, String reqId) {
        this.ctx = ctx;
        this.reqId = reqId;
        value prefix = this.incomingRequestMsgPrefix(isTls, isHTTP2, chost);
        value f = this.first = prefix + this.dumpSReq(ctx.request(), "");
        trace(LogType.sreq, f, null);
    }

    shared actual void nextHopResolved(Proxy.Target nextHop) {
        super.nextHopResolved(nextHop);
        marker = MarkerManager.getMarker(nextHop.hostHeader); // TODO .logBase should be transported here
        assert(exists f = first);
        trace(LogType.sreq, f, null);
    }

    shared actual void trace(SimpleLogProxyTracer.LogType logType, String msg, Throwable? t) {
        logger.trace(marker, logType.graphic + " [" + reqId + "] " + msg, t);
    }
}

"Run the module `org.otherone.vhostproxy`."
shared void run() {
    setupLogging();
    log.info("Starting..    ");

    // TODO timeouts
    // TODO test responses without body e.g. 204
    value myVertx = Vertx.vertx();
    value verticle = MyVerticle();
    myVertx.deployVerticle(verticle, DeploymentOptions(), object satisfies Handler<AsyncResult<JString>> {
        shared actual void handle(AsyncResult<JString> ar) {
            if (ar.succeeded()) {
                log.info("Verticle deployed, deployment id is: ``ar.result()``");
            } else {
                log.error("Verticle deployment failed!", ar.cause());
            }
        }
    });
}

void setupLogging() {
    addLogWriter((Priority priority, Category category, String message, Throwable? throwable) {
        value logger = LogManager.getLogger(category.string);
        value level = switch(priority) case(trace) Level.trace case(debug) Level.debug case(info) Level.info case(warn) Level.warn case(error) Level.error case(fatal) Level.fatal else Level.info;
        if (logger.isEnabled(level)) {
            logger.log(level, message, throwable);
        }
    });
    defaultPriority = trace;
    value filePath = parsePath("log4j2.xml");
    if (filePath.resource is File) {
        System.setProperty("log4j.configurationFile", "log4j2.xml");
    }
    System.setProperty("java.util.logging.manager", "org.apache.logging.log4j.jul.LogManager");
    System.setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.Log4j2LogDelegateFactory");
    //logger = LogManager.hgetLogger(javaClass<NitorBackend>());
}

shared class MyVerticle() extends AbstractVerticle() {
    shared actual void start() {
        log.info("Verticle starting..");

        value client = vertx.createHttpClient(HttpClientOptions()
            .setConnectTimeout(10)
            .setIdleTimeout(120)
            .setMaxPoolSize(1000)
            .setPipelining(false)
            .setPipeliningLimit(1)
            .setMaxWaitQueueSize(20)
            .setUsePooledBuffers(true)
            .setProtocolVersion(HttpVersion.http11)
            .setTryUseCompression(false)
        );

        value router = Router.router(vertx);
        object targetResolver satisfies Proxy.TargetResolver {
            shared actual void resolveNextHop(RoutingContext routingContext, Handler<Proxy.Target> targetHandler) {
                try {
                    value isTls = if (exists scheme = routingContext.request().scheme()) then scheme == "https" else false;
                    value nextHop = resolveNextHop2(routingContext.request(), isTls);
                    if (exists nextHop) {
                        targetHandler.handle(Proxy.Target (
                            nextHop.socketHost,
                            nextHop.socketPort,
                            nextHop.uri,
                            nextHop.hostHeader
                        ));
                    }
                } catch (Throwable e) {
                    log.error("Error", e);
                }
            }
        }
        Proxy proxy = Proxy(client, targetResolver, serverIdleTimeout, 300, object satisfies Supplier<ProxyTracer> {
            get() => MyLogProxyTracer();
        }, Proxy.DefaultPumpStarter());
        router.route().handler(proxy.handle);
        router.route().failureHandler(object satisfies Handler<RoutingContext> {
            shared actual void handle(RoutingContext routingContext) {
                if (routingContext.failed()) {
                    assert (is Proxy.ProxyException ex = routingContext.failure());
                    if (!routingContext.response().headWritten()) {
                        value statusMsg = if (exists cause = ex.cause) then cause.message else (ex.reason == RejectReason.noHostHeader then "Exhausted resources while trying to extract Host header from the request" else "");
                        routingContext.response().setStatusCode(ex.statusCode);
                        routingContext.response().headers().set("content-type", "text/plain;charset=UTF-8");
                        routingContext.response().end(statusMsg);
                    }
                } else {
                    routingContext.next ();
                }
            }
        });

        vertx.createHttpServer(HttpServerOptions()
            //.setCompressionSupported(true)
            // .setHandle100ContinueAutomatically(false)
            .setReuseAddress(true)
            .setIdleTimeout(serverIdleTimeout)
        )
            .requestHandler(router.accept)
            .listen(portConfig.listenHttpPort, object satisfies Handler<AsyncResult<HttpServer>> {
            shared actual void handle(AsyncResult<HttpServer> ar) {
                if (ar.succeeded()) {
                    log.info("HTTP Started on port ``portConfig.listenHttpPort``, sample public url: http://localhost:``portConfig.publicHttpPort``/");
                } else {
                    log.error("HTTP failed on port ``portConfig.listenHttpPort``", ar.cause());
                }
            }
        });

        /*
           tc(ProxyService(client, false, vertx).requestHandler))
         */
        /*
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
        */
        log.info("Startup initialized.");
    }
}


