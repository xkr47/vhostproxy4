import io.netty.bootstrap {
    ServerBootstrap
}
import io.netty.buffer {
    Unpooled
}
import io.netty.channel {
    EventLoopGroup,
    ChannelOption,
    Channel,
    ChannelInitializer,
    ChannelPipeline,
    ChannelInboundHandlerAdapter,
    ChannelHandlerContext,
    ChannelFutureListener
}
import io.netty.channel.nio {
    NioEventLoopGroup
}
import io.netty.channel.socket {
    SocketChannel
}
import io.netty.channel.socket.nio {
    NioServerSocketChannel
}
import io.netty.handler.codec.http {
    HttpServerCodec,
    HttpRequest,
    HttpHeaders { Names { ...  }, Values },
    FullHttpResponse,
    DefaultFullHttpResponse,
    HttpResponseStatus { ... },
    HttpVersion { ... }
}
import io.netty.handler.logging {
    LoggingHandler,
    LogLevel
}
import io.netty.handler.ssl {
    SslContext
}
import ceylon.interop.java {
    javaClass,
    createJavaByteArray,
    javaClassFromInstance
}
import java.lang {
    JInteger = Integer
}
import ceylon.collection {
    ArrayList
}

class HttpHelloWorldServerInitializer(SslContext? sslCtx) extends ChannelInitializer<SocketChannel>() {
    shared actual void initChannel(SocketChannel ch) {
        ChannelPipeline p = ch.pipeline();
        if (exists sslCtx) {
            p.addLast(sslCtx.newHandler(ch.alloc()));
        }
        p.addLast(HttpServerCodec());
        p.addLast(HttpHelloWorldServerHandler());
    }
}

class HttpHelloWorldServerHandler() extends ChannelInboundHandlerAdapter() {
    Byte[] content = [ 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd' ].map((Character element) => element.integer.byte).sequence();
    
    shared actual void channelReadComplete(ChannelHandlerContext ctx) {
        ctx.flush();
    }
    
    shared actual void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (is HttpRequest msg)  {
            print("Got msg " + javaClassFromInstance(msg).string);
            value req = msg;
            
            if (HttpHeaders.is100ContinueExpected(req)) {
                ctx.write(DefaultFullHttpResponse(\iHTTP_1_1, \iCONTINUE));
            }
            Boolean keepAlive = HttpHeaders.isKeepAlive(req);
            FullHttpResponse response = DefaultFullHttpResponse(\iHTTP_1_1, \iOK, Unpooled.wrappedBuffer(createJavaByteArray(content)));
            response.headers().set(\iCONTENT_TYPE, "text/plain");
            response.headers().set(\iCONTENT_LENGTH, response.content().readableBytes());
            
            if (!keepAlive) {
                ctx.write(response).addListener(ChannelFutureListener.\iCLOSE);
            } else {
                response.headers().set(\iCONNECTION, Values.\iKEEP_ALIVE);
                ctx.write(response);
            }
        }
    }
    
    shared actual void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}
"Run the module `org.otherone.vhostproxy.netty`."
shared void run() {
    value ssl = false;
    value sslCtx = null;
    value port = 8080;
    
    EventLoopGroup bossGroup = NioEventLoopGroup(1);
    EventLoopGroup workerGroup = NioEventLoopGroup();
    try {
        ServerBootstrap b = ServerBootstrap();
        b.option(ChannelOption.\iSO_BACKLOG, JInteger(1024));
        b.group(bossGroup, workerGroup)
                .channel(javaClass<NioServerSocketChannel>())
                .handler(LoggingHandler(LogLevel.\iINFO))
                .childHandler(HttpHelloWorldServerInitializer(sslCtx));
        
        Channel ch = b.bind(port).sync().channel();
        
        print("Open your web browser and navigate to " +
            (ssl then "https" else "http") + "://127.0.0.1:" + port.string + "/");
        
        ch.closeFuture().sync();
    } finally {
        bossGroup.shutdownGracefully();
        workerGroup.shutdownGracefully();
    } 
}