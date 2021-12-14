package com.romanishuna.security.lab.service;

import com.romanishuna.security.lab.exception.BadRequestException;
import com.romanishuna.security.lab.exception.NotFoundException;
import com.romanishuna.security.lab.model.*;
import com.romanishuna.security.lab.repository.UserRepo;
import com.romanishuna.security.lab.wrapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

        @Autowired
        private UserRepo userRepository;
        @Autowired
        private UserMapper userMapper;
        @Autowired
        private AuthenticationManager authenticationManager;
        @Autowired
        private TokenUtilService tokenUtilService;
        @Autowired
        private PasswordEncoder passwordEncoder;

        public void registration(UserRegistration userDTO) {

                if (userRepository.findUserByEmail(userDTO.getEmail()) != null) {
                        throw new BadRequestException("User with email: " + userDTO.getEmail() + " is already existed.");
                }
                User user = userMapper.dtoToEntity(userDTO);
                user.setPassword(passwordEncoder.encode(user.getPassword()));
                userRepository.save(user);
        }

        public Token login(UserLogin userLogin) {
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userLogin.getEmail(), userLogin.getPassword()));
                UserDetails userDetails = loadUserByUsername(userLogin.getEmail());
                return new Token("Bearer " + tokenUtilService.generateTOKEN(userDetails));
        }

        @Override
        public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
                return new UserDetailsImplementation(findUserByEmail(s));
        }

        public User findUserByEmail(String email) {
                return Optional.of(userRepository.findUserByEmail(email))
                        .orElseThrow(() -> new NotFoundException("User with email: " + email + " wasn't found."));
        }
}
