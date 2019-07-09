package com.fred.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class CloudoerGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(CloudoerGatewayApplication.class, args);
    }

}
