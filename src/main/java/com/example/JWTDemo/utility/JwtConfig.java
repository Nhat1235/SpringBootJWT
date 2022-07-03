package com.example.JWTDemo.utility;

public class JwtConfig {
    private static String SECRET_KEY;
    private static String ACCESS_TOKEN_TIMEOUT;
    private static String REFRESH_TOKEN_TIMEOUT;

    public JwtConfig(){
    }

    public static String getSecretKey() {
        return SECRET_KEY;
    }

    public static String getAccessTokenTimeout() {
        return ACCESS_TOKEN_TIMEOUT;
    }

    public static String getRefreshTokenTimeout() {
        return REFRESH_TOKEN_TIMEOUT;
    }

    public static void setSecretKey(String secretKey) {
        SECRET_KEY = secretKey;
    }

    public static void setAccessTokenTimeout(String accessTokenTimeout) {
        ACCESS_TOKEN_TIMEOUT = accessTokenTimeout;
    }

    public static void setRefreshTokenTimeout(String refreshTokenTimeout) {
        REFRESH_TOKEN_TIMEOUT = refreshTokenTimeout;
    }
}


