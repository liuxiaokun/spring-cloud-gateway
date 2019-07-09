package com.byx.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.toList;

//@Component
@Slf4j
public class PermissionFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String secret;

    @Autowired
    private RedisTemplate redisTemplate;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        String requestURI = request.getURI().getPath();
        String method = request.getMethodValue();
        log.info("requestURI:{}, method:{}", requestURI, method);

        HttpHeaders headers = request.getHeaders();
        List<String> authorization = headers.get("Authorization");

        if (null == authorization || authorization.size() < 1) {
            byte[] bytes = "{\"code\":\"10400\",\"message\":\"token can not be null\"}".getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
            return response.writeWith(Flux.just(buffer));
        }

        String token = authorization.get(0);
        log.info("token:{}", token);
        token = token.replace("Bearer ", "");
        Claims claims;
        claims = Jwts.parser().setSigningKey(secret.getBytes()).parseClaimsJws(token).getBody();
        Long userId = Long.valueOf(claims.getSubject());
        log.info("userId:{}", userId);
        Date expiration = claims.getExpiration();

        if (expiration.before(new Date())) {
            byte[] bytes = "{\"code\":\"10400\",\"message\":\"token expired\"}".getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
            return response.writeWith(Flux.just(buffer));
        }

        // permission check
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        List<String> roleNames = (List<String>) claims.get("authorities");
        log.info("roleNames:{}", roleNames.toArray());

        Map<String, List<String>> rolesPerms = (Map) redisTemplate.opsForHash().entries("roles-permissions");
        log.info("rolesPerms:{}", rolesPerms.size());

        List<String> allowRoleNames = new ArrayList<>();
        for (Map.Entry<String, List<String>> temp : rolesPerms.entrySet()) {
            String roleName = temp.getKey();
            List<String> permissionUrls = temp.getValue();

            if (!CollectionUtils.isEmpty(permissionUrls)) {
                for (String permissionUrl : permissionUrls) {

                    //对于菜单级别得通配符匹配。
                    if (permissionUrl.startsWith("ALL:")) {
                        permissionUrl = method + ":" + permissionUrl.substring(4);
                    }
                    if (antPathMatcher.match(permissionUrl, method + ":" + requestURI)) {
                        allowRoleNames.add(roleName);
                        break;
                    }
                }
            }
        }

        log.info("allowRoleNames:{}", allowRoleNames.toArray());
        List<String> interSection = roleNames.stream().filter(item -> allowRoleNames.contains(item)).collect(toList());
        log.info("interSection:{}", interSection.toArray());

        if (!(allowRoleNames.size() == 0 || interSection.size() > 0)) {
            byte[] bytes = "{\"code\":\"10400\",\"message\":\"has no privilege\"}".getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            response.setStatusCode(HttpStatus.FORBIDDEN);
            response.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
            return response.writeWith(Flux.just(buffer));
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
