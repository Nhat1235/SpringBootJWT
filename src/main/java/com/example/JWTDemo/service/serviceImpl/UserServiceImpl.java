package com.example.JWTDemo.service.serviceImpl;

import com.example.JWTDemo.domain.Role;
import com.example.JWTDemo.domain.User;
import com.example.JWTDemo.repository.RoleRepository;
import com.example.JWTDemo.repository.UserRepository;
import com.example.JWTDemo.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor //tao constructor cho DI, bean
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            log.error("No such user in the database");
            throw new UsernameNotFoundException("User not found in database!");
        } else {
            log.info("User {} found in database", user.getName());
        }
        Collection<SimpleGrantedAuthority> grantedAuthorities = new ArrayList<>();
        user.getRoles().forEach(e -> {
            grantedAuthorities.add(new SimpleGrantedAuthority(e.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), grantedAuthorities);
    }

    @Override
    public User saveUser(User user) {
        log.info("Saving user {} to database", user.getName());
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving role {} to database", role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to user {}", roleName, username);
        User user = userRepository.findByUsername(username);
        Role role = roleRepository.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        log.info("fetching user {}", username);
        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> getUser() {
        log.info("fetching user");
        return userRepository.findAll();
    }


}
