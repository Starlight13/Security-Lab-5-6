package com.romanishuna.security.lab.web;

import com.romanishuna.security.lab.model.Message;
import com.romanishuna.security.lab.model.Token;
import com.romanishuna.security.lab.model.UserLogin;
import com.romanishuna.security.lab.model.UserRegistration;
import com.romanishuna.security.lab.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
    public ResponseEntity<Message> login(@RequestBody UserRegistration userRegistration) {
        userService.registration(userRegistration);
        return new ResponseEntity<>(new Message("User was registered =)"), HttpStatus.OK);
    }
}
