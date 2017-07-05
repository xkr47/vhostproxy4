import ceylon.file {
    parsePath,
    File
}
import ceylon.interop.java {
    javaClass
}
import ceylon.logging {
    logger,
    Logger,
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

import io.nitor.api.backend.proxy {
    ...
}
import io.vertx.core {
    ...
}
import io.vertx.core.buffer {
    Buffer
}
import io.vertx.core.http {
    ...
}
import io.vertx.core.streams {
    ReadStream,
    WriteStream
}
import io.vertx.ext.web {
    Router,
    RoutingContext
}

import java.lang {
    JString=String,
    System,
    Void,
    RuntimeException
}
import java.util.\ifunction {
    Supplier
}

import org.apache.logging.log4j {
    LogManager,
    Level,
    Log4jLogger=Logger,
    Marker,
    MarkerManager
}
import io.nitor.vertx.acme4j.util {
    DynamicCertOptions,
    SetupHttpServerOptions,
    DynamicCertManager
}
import io.nitor.vertx.acme4j {
    AcmeManager
}
import com.fasterxml.jackson.datatype.jsr310 {
    JavaTimeModule
}
import com.fasterxml.jackson.databind.\imodule {
    SimpleModule
}
import com.fasterxml.jackson.databind {
    Module
}
import com.fasterxml.jackson.core {
    Version
}

Logger log = logger(`package`);

class MyPump(Marker? marker, String reqId, MyLogProxyTracer.LogType logType, String type, ReadStream<Buffer> readStream, WriteStream<Buffer> writeStream, Boolean dumpBody, Log4jLogger logger, Anything()? firstBufferWrittenHandler = null) {
    void dataHandler(Buffer data) {
        writeStream.write(data);
        if (exists firstBufferWrittenHandler) { firstBufferWrittenHandler(); }

        StringBuilder sb = StringBuilder().append("``logType.graphic`` [``reqId``] ``data.length()`` bytes``dumpBody then ":" else ""``");
        if (dumpBody) {
            sb.append("\n");
            value prefix = "``MyLogProxyTracer.LogType.none.graphic`` [``reqId``] ";
            variable value start = 0;
            for (i in 0:data.length()) {
                if (data.getUnsignedByte(i) == '\n'.integer) {
                    sb.append(prefix);
                    sb.append(data.slice(start, i + 1).string);
                    start = i+1;
                }
            }
            sb.append(prefix);
            sb.append(data.slice(start, data.length()).string);
        }
        logger.trace(marker, sb.string);

        if (writeStream.writeQueueFull()) {
            readStream.pause();
            writeStream.drainHandler(object satisfies Handler<Void> {
                handle(Void v) => readStream.resume();
            });
        }
    }

    shared void start() {
        readStream.handler(tc(dataHandler));
    }
}

class Target (
    shared String socketHost,
    shared Integer socketPort,
    shared String uri,
    shared String hostHeader,
    shared String logBase
){}

shared class RejectReason of incomingRequestFail | outgoingRequestFail | incomingResponseFail | noHostHeader {
    shared new incomingRequestFail {}
    shared new outgoingRequestFail {}
    shared new incomingResponseFail {}
    shared new noHostHeader {}
}

class MyLogProxyTracer() extends SimpleLogProxyTracer() {

    variable String? first = null;
    shared variable Marker? marker = null;
    shared Log4jLogger loggr = LogManager.getLogger(javaClass<MyLogProxyTracer>());
    shared String getReqId() => reqId;

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
        loggr.trace(marker, logType.graphic + " [" + reqId + "] " + msg, t);
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
    myVertx.exceptionHandler((e) {
        log.error("Fallback exception handler got", e);
    });
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

class MyPumpStarter()
         satisfies Proxy.PumpStarter {
    shared actual void start(Proxy.PumpStarter.Type type, ReadStream<Buffer> rs, WriteStream<Buffer> ws, ProxyTracer t) {
        assert(is MyLogProxyTracer t);
        switch (type)
        case(Proxy.PumpStarter.Type.request) {
            MyPump(t.marker, t.getReqId(), MyLogProxyTracer.LogType.reqbody, "Request body", rs, ws, dumpRequestBody, t.loggr).start();
        }
        case(Proxy.PumpStarter.Type.response) {
            MyPump(t.marker, t.getReqId(), MyLogProxyTracer.LogType.resbody, "Response body", rs, ws, dumpResponseBody, t.loggr).start();
        }
        else {
            MyPump(t.marker, t.getReqId(), MyLogProxyTracer.LogType.none, "Unknown body", rs, ws, false, t.loggr).start();
        }
    }
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
        }, MyPumpStarter());
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
            // .setHandle100ContinueAutomatically(false)
            .setReuseAddress(true)
            .setCompressionSupported(false) // otherwise it automatically compresses based on response headers even if pre-compressed with e.g. proxy
            .setUsePooledBuffers(true)
            .setIdleTimeout(serverIdleTimeout)
        )
            .requestHandler(router.accept)
            .listen(portConfig.listenHttpPort, object satisfies Handler<AsyncResult<HttpServer>> {
            shared actual void handle(AsyncResult<HttpServer> ar) {
                if (ar.succeeded()) {
                    log.info("HTTP started on port ``portConfig.listenHttpPort``, sample public url: http://localhost:``portConfig.publicHttpPort``/");
                } else {
                    log.error("HTTP failed on port ``portConfig.listenHttpPort``", ar.cause());
                }
            }
        });

        // TLS

        value dynamicCertOptions = DynamicCertOptions();
        value certManager = DynamicCertManager(vertx, dynamicCertOptions);
        value httpServerOptions = SetupHttpServerOptions.createHttpServerOptions(dynamicCertOptions, true)
            .setIdleTimeout(serverIdleTimeout);
        vertx.createHttpServer(httpServerOptions)
            .requestHandler(object satisfies Handler<HttpServerRequest> {
            shared actual void handle(HttpServerRequest request) {
                router.accept(request);
            }
        })
            .listen(portConfig.listenHttpsPort, object satisfies Handler<AsyncResult<HttpServer>> {
            shared actual void handle(AsyncResult<HttpServer> ar) {
                if (ar.succeeded()) {
                    log.info("HTTPS started on port ``portConfig.listenHttpsPort``, sample public url: https://localhost:``portConfig.publicHttpsPort``/");
                } else {
                    log.error("HTTPS failed on port ``portConfig.listenHttpsPort``", ar.cause());
                    return;
                }

                object xx extends Module() {
                    shared actual String moduleName => nothing;
                    shared actual void setupModule(Module.SetupContext? context) {}
                    shared actual Version version() => nothing;
                }

                value acmeMgr = AcmeManager(vertx, certManager, ".acmemanager");
                acmeMgr.readConf("acme.json", "conf").compose((conf) => acmeMgr.start(conf)).setHandler((ar) {
                    if (ar.failed()) {
                        log.error("AcmeManager start failed", ar.cause());
                        return;
                    }
                    log.info("AcmeManager start successful");
                }
                );
            }
        });

        log.info("Startup initialized.");
    }
}
