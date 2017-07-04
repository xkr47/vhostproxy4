native("jvm") module org.otherone.vhostproxy.vertx "4" {
    //shared import io.vertx.ceylon.core "3.4.0";

    shared import maven:io.nitor.api:"backend" "1.9";

    shared import maven:io.vertx:"vertx-core" "3.4.1";
    shared import maven:io.vertx:"vertx-web" "3.4.1";

    import maven:org.apache.logging.log4j:"log4j-api" "2.8.2";
    import maven:org.apache.logging.log4j:"log4j-core" "2.8.2";
    // required by log4j asynclongger
    import maven:com.lmax:"disruptor" "3.3.6";
    import maven:org.apache.logging.log4j:"log4j-1.2-api" "2.8.2";
    import maven:org.apache.logging.log4j:"log4j-jcl" "2.8.2";
    import maven:org.apache.logging.log4j:"log4j-slf4j-impl" "2.8.2";
    import maven:org.apache.logging.log4j:"log4j-jul" "2.8.2";


    import maven:io.netty:"netty-common" "4.1.9.Final";
    import maven:io.netty:"netty-buffer" "4.1.9.Final";
    import maven:io.netty:"netty-transport" "4.1.9.Final";
    import maven:io.netty:"netty-handler" "4.1.9.Final";
    import maven:io.netty:"netty-handler-proxy" "4.1.9.Final";
    import maven:io.netty:"netty-codec-http" "4.1.9.Final";
    import maven:io.netty:"netty-codec-http2" "4.1.9.Final";
    import maven:io.netty:"netty-resolver" "4.1.9.Final";
    import maven:io.netty:"netty-resolver-dns" "4.1.9.Final";

    import ceylon.collection "1.3.2";

    //shared import "io.vertx:vertx-lang-ceylon" "3.3.0-SNAPSHOT";
    //shared import "io.vertx.lang.ceylon" "3.3.0-SNAPSHOT";
    import ceylon.regex "1.3.2";
    import ceylon.logging "1.3.2";
    //import ceylon.time "1.2.1";
    import java.base "7";
    //import "it.zero11:acme-client" "0.1.2";
    import ceylon.file "1.3.2";
    import ceylon.buffer "1.3.2";
    import ceylon.interop.java "1.3.2";
}
