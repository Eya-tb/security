package com.example.security.config;

import com.example.security.services.TSAClient;
import com.example.security.services.TSAClientBouncyCastle;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TSAConfig {
    @Value("${tsa.url}")
    private String tsaUrl;

    @Value("${tsa.connect-timeout:5000}")
    private int connectTimeout;

    @Value("${tsa.read-timeout:10000}")
    private int readTimeout;

    @Bean
    public TSAClient tsaClient() {
        return new TSAClientBouncyCastle(tsaUrl, connectTimeout, readTimeout);
    }
}