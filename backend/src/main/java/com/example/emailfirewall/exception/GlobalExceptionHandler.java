package com.example.emailfirewall.exception;

import com.example.emailfirewall.dto.IngestErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.io.IOException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<IngestErrorResponse> handleInvalidCredentials(InvalidCredentialsException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new IngestErrorResponse(e.getMessage(), "INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED.value()));
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<IngestErrorResponse> handleUserExists(UserAlreadyExistsException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new IngestErrorResponse(e.getMessage(), "USER_EXISTS", HttpStatus.CONFLICT.value()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<IngestErrorResponse> handleInvalidFormat(IllegalArgumentException e) {
        return ResponseEntity.badRequest()
                .body(new IngestErrorResponse(e.getMessage(), "INVALID_FORMAT", HttpStatus.BAD_REQUEST.value()));
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<IngestErrorResponse> handleIOError(IOException e) {
        return ResponseEntity.badRequest()
                .body(new IngestErrorResponse("Failed to read file", "IO_ERROR", HttpStatus.BAD_REQUEST.value()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<IngestErrorResponse> handleGenericException(Exception e) {
        int status = HttpStatus.INTERNAL_SERVER_ERROR.value();
        return ResponseEntity.status(status).body(
                new IngestErrorResponse(
                        e.getClass().getSimpleName() + ": " + (e.getMessage() != null ? e.getMessage() : ""),
                        "INTERNAL_ERROR",
                        status
                )
        );
    }
}
