package com.example.JWTDemo.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.JWTDemo.domain.Role;
import com.example.JWTDemo.domain.User;
import com.example.JWTDemo.dto.UserDto;
import com.example.JWTDemo.service.UserService;
import com.example.JWTDemo.utility.JwtConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping(value = "/api")
public class UserController {
    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers() {
        return ResponseEntity.ok().body(userService.getUser());
    }

    @PostMapping("/users/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/users/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/add-to-user")
    public ResponseEntity<?> addRoleToUser(@RequestBody UserDto dto) {
        userService.addRoleToUser(dto.getUsername(), dto.getRoleName());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/token/refresh-token")
    public void refreshToken(HttpServletResponse response, HttpServletRequest request) throws IOException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256(JwtConfig.getSecretKey().getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);
                String username = decodedJWT.getSubject();
                User user = userService.getUser(username);

                Map<String, String> tokens = new HashMap<>();
                tokens.put("issuer", request.getRequestURL().toString());
                tokens.put("access_token", renewAccessToken(user, algorithm, request));
                tokens.put("refresh_token", refresh_token);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);

            } catch (Exception e) {
                log.error("An Error has occurred: {} ", e.getMessage());
                response.setHeader("error", e.getMessage());
                response.setStatus(403);
                Map<String, String> error = new HashMap<>();
                error.put("error_message", e.getMessage());
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh token is missing!");
        }
    }

    public String renewAccessToken(User user, Algorithm algorithm, HttpServletRequest request) {
        String access_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtConfig.getAccessTokenTimeout()))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .sign(algorithm);
        return access_token;
    }
}

