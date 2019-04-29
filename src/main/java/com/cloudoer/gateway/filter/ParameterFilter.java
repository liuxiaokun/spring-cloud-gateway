package com.cloudoer.gateway.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import io.netty.buffer.ByteBufAllocator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.NettyDataBufferFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

import static org.springframework.web.bind.annotation.RequestMethod.*;

import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @author liuxiaokun
 * @version 1.0.0
 * @date 2019-04-29
 */
@Slf4j
@Component
public class ParameterFilter implements GlobalFilter, Ordered {

    private static final String OBJECT_PREFIX = "{";
    private static final String ARRAY_PREFIX = "[";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        RequestMethod method = RequestMethod.valueOf(request.getMethodValue());
        URI uri = request.getURI();

        if (POST.equals(method) || PUT.equals(method) || PATCH.equals(method)) {
            String body = resolveBody(request);
            String newBody;

            boolean needHandling = null != body && (body.startsWith(OBJECT_PREFIX) || body.startsWith(ARRAY_PREFIX));
            if (needHandling) {
                if (body.startsWith(OBJECT_PREFIX)) {
                    JSONObject parse = JSON.parseObject(body);
                    newBody = dgObject(parse);
                } else {
                    JSONArray parse = JSON.parseArray(body);
                    for (Object temO : parse) {
                        JSONObject tempObject = (JSONObject) temO;
                        dgObject(tempObject);
                    }
                    newBody = parse.toString();
                }

                ServerHttpRequest newRequest = request.mutate().uri(uri).build();
                DataBuffer bodyDataBuffer = stringBuffer(newBody);
                Flux<DataBuffer> bodyFlux = Flux.just(bodyDataBuffer);

                request = new ServerHttpRequestDecorator(newRequest) {
                    @Override
                    public Flux<DataBuffer> getBody() {
                        return bodyFlux;
                    }
                };
                return chain.filter(exchange.mutate().request(request).build());
            }
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 1;
    }

    private String resolveBody(ServerHttpRequest serverHttpRequest) {
        Flux<DataBuffer> body = serverHttpRequest.getBody();
        AtomicReference<String> bodyRef = new AtomicReference<>();
        body.subscribe(buffer -> {
            CharBuffer charBuffer = StandardCharsets.UTF_8.decode(buffer.asByteBuffer());
            DataBufferUtils.release(buffer);
            bodyRef.set(charBuffer.toString());
        });
        return bodyRef.get();
    }

    private DataBuffer stringBuffer(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);

        NettyDataBufferFactory nettyDataBufferFactory = new NettyDataBufferFactory(ByteBufAllocator.DEFAULT);
        DataBuffer buffer = nettyDataBufferFactory.allocateBuffer(bytes.length);
        buffer.write(bytes);
        return buffer;
    }

    private String dgObject(JSONObject parse) {
        Set<String> keys = parse.keySet();

        for (String temp : keys) {

            log.info("temp:{}", temp);
            boolean isString = true;
            try {
                String value = (String) parse.get(temp);
            } catch (ClassCastException e) {
                isString = false;
            }

            if (isString && null != parse.get(temp)) {
                log.info("write value:{}", parse.get(temp));
                /*TODO XSS攻击 HtmlUtils.htmlEscape("");*/
                parse.put(temp, parse.getString(temp).trim());
            }

            boolean isJsonObject = true;
            try {
                JSONObject jsonObject = (JSONObject) parse.get(temp);
            } catch (ClassCastException e) {
                isJsonObject = false;
            }

            if (isJsonObject && null != parse.get(temp)) {
                dgObject((JSONObject) parse.get(temp));
            }

            boolean isJsonArray = true;
            JSONArray jsonArray = null;
            try {
                jsonArray = (JSONArray) parse.get(temp);
            } catch (ClassCastException e) {
                isJsonArray = false;
            }
            if (isJsonArray && null != parse.get(temp)) {

                for (Object temO : jsonArray) {
                    JSONObject tempObject = (JSONObject) temO;
                    dgObject(tempObject);
                }
            }
        }
        return parse.toString();
    }
}
