package com.example.JWTDemo;

import com.example.JWTDemo.domain.Role;
import com.example.JWTDemo.domain.User;
import com.example.JWTDemo.service.UserService;
import com.example.JWTDemo.utility.FileReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JWTDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(JWTDemoApplication.class, args);
    }

    @Value("${jwt.config.path}")
    String jwtPath;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner runner(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null, "ADMIN", "ADMIN", "admin", new ArrayList<>()));

            userService.addRoleToUser("ADMIN", "ROLE_ADMIN");
            userService.addRoleToUser("ADMIN", "ROLE_SUPER_ADMIN");

        };
    }

    @Bean
    CommandLineRunner runner2(FileReader reader){
        return args -> {
            reader.readFile(jwtPath);
        };
    }
}
