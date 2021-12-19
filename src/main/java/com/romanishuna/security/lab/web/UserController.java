package com.romanishuna.security.lab.web;

import com.romanishuna.security.lab.model.Token;
import com.romanishuna.security.lab.model.UserDetailsResponse;
import com.romanishuna.security.lab.model.UserLogin;
import com.romanishuna.security.lab.model.UserRegistration;
import com.romanishuna.security.lab.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public ResponseEntity<Token> login(@RequestBody UserLogin userLogin) {
        return new ResponseEntity<>(userService.login(userLogin), HttpStatus.OK);
    }

    @PostMapping("/registration")
    public ResponseEntity<String> registration(@RequestBody UserRegistration userRegistration) {
        userService.registration(userRegistration);
        return new ResponseEntity<>("Registration successful :)", HttpStatus.OK);
    }

    @GetMapping("/info")
    public ResponseEntity<UserDetailsResponse> info() {
        return new ResponseEntity<>(userService.getUserDetails(), HttpStatus.OK);
    }
}
