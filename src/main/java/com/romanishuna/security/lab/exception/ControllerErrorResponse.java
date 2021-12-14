package com.romanishuna.security.lab.exception;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ControllerErrorResponse {
    private String errorCode;
    private String message;
}
