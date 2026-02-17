package com.example.emailfirewall.exception;

public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException() {
        super("Invalid Credentials");
    }

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
