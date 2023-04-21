package com.danslogin.login.service;

import java.util.ArrayList;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.danslogin.login.model.User;
import com.danslogin.login.repository.UserRepository;

@Service
public class UserService implements UserDetailsService {
    private final UserRepository userRepo;

    @Autowired
    private JwtTokenUtil jwtUtil;

    public UserService(UserRepository userRepo) {
        this.userRepo = userRepo;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("Invalid username or password");
        }

        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                user.getPassword(),
                new ArrayList<>());
    }

    public String login(String username, String password) {
        JwtUserDetailsService jwtUserDetailsService = new JwtUserDetailsService();
        Authentication authentication = authenticate(username, password);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);

        return jwtUtil.generateToken(userDetails);
    }

    private Authentication authenticate(String username, String password) {
        try {
            Authentication authentication = authenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>()));

            return authentication;
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    private AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(authenticationProvider()));
    }

    private AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(this);
        provider.setPasswordEncoder(new BCryptPasswordEncoder());
        return provider;
    }
}
