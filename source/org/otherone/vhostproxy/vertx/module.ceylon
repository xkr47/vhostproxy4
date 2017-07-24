native("jvm") module org.otherone.vhostproxy.vertx "4.1" {
    //shared import io.vertx.ceylon.core "3.4.0";

    shared import maven:io.nitor.api:"backend" "1.9";

    import maven:space.xkr47.vertx:"vertx-acme4j" "0.1-SNAPSHOT";
    //import maven:org.mortbay.jetty.alpn:"jetty-alpn-agent" "2.0.6";
    import maven:org.mortbay.jetty.alpn:"alpn-boot" "8.1.11.v20170118";
// -javaagent:/home/xkr47/jonas/.m2/repository/org/mortbay/jetty/alpn/jetty-alpn-agent/2.0.6/jetty-alpn-agent-2.0.6.jar
/*
    shared import maven:com.fasterxml.jackson.datatype:"jackson-datatype-jsr310" "2.8.8";
    shared import maven:com.fasterxml.jackson.core:"jackson-databind" "2.8.8";
    shared import maven:com.fasterxml.jackson.core:"jackson-core" "2.8.8";
    shared import maven:com.fasterxml.jackson.core:"jackson-annotations" "2.8.0";
    shared import maven:org.shredzone.acme4j:"acme4j-client" "0.9";
    shared import maven:org.shredzone.acme4j:"acme4j-utils" "0.9";
*/
    shared import maven:io.vertx:"vertx-core" "3.4.1";
    shared import maven:io.vertx:"vertx-web" "3.4.1";

    import com.redhat.ceylon.model "1.3.2";
    import ceylon.runtime "1.3.2";
    import org.jboss.modules "1.4.4.Final";

    import maven:org.apache.logging.log4j:"log4j-api" "2.8.2";
    import maven:org.apache.logging.log4j:"log4j-core" "2.8.2";
    import maven:org.apache.logging.log4j:"log4j-1.2-api" "2.8.2";
    import maven:org.apache.logging.log4j:"log4j-jcl" "2.8.2";
    import maven:org.apache.logging.log4j:"log4j-jul" "2.8.2";

//    import maven:org.eclipse.jetty.osgi:"jetty-osgi-alpn" "9.4.6.v20170531";

    import maven:io.netty:"netty-codec-http" "4.1.9.Final";

    import ceylon.collection "1.3.2";

    //shared import "io.vertx:vertx-lang-ceylon" "3.3.0-SNAPSHOT";
    //shared import "io.vertx.lang.ceylon" "3.3.0-SNAPSHOT";
    import ceylon.regex "1.3.2";
    import ceylon.logging "1.3.2";
    //import ceylon.time "1.2.1";
    import java.base "8";
    //import "it.zero11:acme-client" "0.1.2";
    import ceylon.file "1.3.2";
    import ceylon.buffer "1.3.2";
    import ceylon.interop.java "1.3.2";
}
