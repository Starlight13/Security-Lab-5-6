package com.romanishuna.security.lab.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserDetailsResponse {
    private String email;
    private String phoneNumber;
}
