package com.romanishuna.security.lab.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class NotFoundException extends RuntimeException {

    private final String message;

    public String getErrorCode() {
        return "not_found";
    }
}
