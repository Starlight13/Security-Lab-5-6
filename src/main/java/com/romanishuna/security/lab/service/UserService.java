package com.romanishuna.security.lab.service;

import com.romanishuna.security.lab.exception.BadRequestException;
import com.romanishuna.security.lab.exception.NotFoundException;
import com.romanishuna.security.lab.model.*;
import com.romanishuna.security.lab.repository.UserRepo;
import com.romanishuna.security.lab.validation.ValidationService;
import com.romanishuna.security.lab.wrapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
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
        @Autowired
        private ValidationService validationService;
        @Autowired
        private DataEncryptionService dataEncryptionService;

        public void registration(UserRegistration userRegistration) {
                validationService.validateEmail(userRegistration.getEmail());
                validationService.validatePassword(userRegistration.getPassword(), userRegistration.getEmail());

                if (userRepository.findUserByEmail(userRegistration.getEmail()) != null) {
                        throw new BadRequestException("User with email: " + userRegistration.getEmail() + " is already existed.");
                }
                User user = userMapper.dtoToEntity(userRegistration);
                user.setPassword(passwordEncoder.encode(user.getPassword()));
                var encryptedResult = dataEncryptionService.encrypt(user.getPhoneNumber(), userRegistration.getPassword());
                if (encryptedResult != null) {
                        user.setPhoneNumber(encryptedResult.cipheredText);
                        user.setDek(encryptedResult.key);
                }
                userRepository.save(user);
        }

        public String decryptValueByDek (String val, String dek) {
                return dataEncryptionService.decrypt(val, dek);
        }

        public UserDetailsResponse getUserDetails() {
                UserDetailsImplementation details = ((UserDetailsImplementation) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
                var decryptedPhoneNumber = decryptValueByDek(details.getUser().getPhoneNumber(), details.getUser().getDek());
                return new UserDetailsResponse(details.getUsername(), decryptedPhoneNumber);
        }

        public Token login(UserLogin userLogin) {
                try {
                        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userLogin.getEmail(), userLogin.getPassword()));
                } catch (Exception e) {
                        throw new BadRequestException("Email or password is invalid :(");
                }
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
