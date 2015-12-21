import io.vertx.ceylon.core { ... }
import io.vertx.ceylon.core.http { ... }
import io.vertx.ceylon.core.streams {
    pump
}

"Run the module `org.otherone.vhostproxy`."
shared void run() {
    print("Starting..");
    value myVertx = vertx.vertx();
    value client = myVertx.createHttpClient();
    myVertx.createHttpServer().requestHandler((HttpServerRequest sreq) {
        value host = "localhost";
        value port = 8090;
        print("Incoming request from : ``sreq.netSocket().localAddress().host()``.. ``sreq.method().name`` ``sreq.uri()``");
        value creq = client.request(sreq.method(), port, host, sreq.uri(), (HttpClientResponse cres) {
            print("Response");
            value sres = sreq.response();
            sres.setStatusCode(cres.statusCode());
            sres.setStatusMessage(cres.statusMessage());
            sres.headers().addAll(cres.headers());
            value resPump = pump.pump(cres, sres);
            cres.endHandler(() { print("Response pumping complete"); return sres.end(); });
            resPump.start();
            print("Response pumping started");
        });
        creq.headers().addAll(sreq.headers());
        value reqPump = pump.pump(sreq, creq);
        sreq.endHandler(() { print("Request pumping complete"); return creq.end(); });
        reqPump.start();
        print("Request pumping started");
        creq.end();
    }
    ).listen(8080);
    print("Started");
}
