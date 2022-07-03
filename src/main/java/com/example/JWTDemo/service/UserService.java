package com.example.JWTDemo.service;

import com.example.JWTDemo.domain.Role;
import com.example.JWTDemo.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUser();
}
