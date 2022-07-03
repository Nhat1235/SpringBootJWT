package com.example.JWTDemo.utility;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@Component
@Slf4j
public class FileReader {

    public void readFile(String filePath) {
        List<String> list;
        try {
            list = Files.readAllLines(Paths.get(filePath), StandardCharsets.UTF_8);
            list.forEach(lines-> {
                if (lines.contains("SECRET_KEY")){
                    JwtConfig.setSecretKey(lines.substring("SECRET_KEY=".length()));
                }else if (lines.contains("ACCESS_TOKEN_TIMEOUT")){
                    JwtConfig.setAccessTokenTimeout(lines.substring("ACCESS_TOKEN_TIMEOUT=".length()));
                }else if (lines.contains("REFRESH_TOKEN_TIMEOUT")){
                    JwtConfig.setRefreshTokenTimeout(lines.substring("REFRESH_TOKEN_TIMEOUT=".length()));
                }
            });
            System.out.println(JwtConfig.getSecretKey());
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }

}
