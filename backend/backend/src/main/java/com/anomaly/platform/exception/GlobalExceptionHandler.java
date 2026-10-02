package com.anomaly.platform.exception;

import com.anomaly.platform.ai.AiProviderUnavailableException;
import com.anomaly.platform.dto.ErrorResponse;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /*
     * ============================================================
     * REQUEST ID
     * ============================================================
     */

    private String requestId() {

        String id = MDC.get("X-Correlation-Id");

        if (id == null || id.isBlank()) {
            return null;
        }

        return id;
    }

    /*
     * ============================================================
     * ERROR RESPONSE BUILDER
     * ============================================================
     */

    private ErrorResponse error(
            String code,
            String message,
            List<String> details
    ) {

        return new ErrorResponse(
                code,
                message,
                details == null
                        ? List.of()
                        : details,
                requestId(),
                OffsetDateTime.now()
        );
    }

    /*
     * ============================================================
     * 404 - RESOURCE NOT FOUND
     * ============================================================
     */

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(
            NotFoundException exception
    ) {

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(
                        error(
                                "NOT_FOUND",
                                exception.getMessage(),
                                List.of()
                        )
                );
    }

    /*
     * ============================================================
     * 409 - DUPLICATE RESOURCE
     * ============================================================
     */

    @ExceptionHandler(PayloadTooLargeException.class)
    public ResponseEntity<ErrorResponse> handlePayloadTooLarge(
            PayloadTooLargeException exception
    ) {

        return ResponseEntity
                .status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(
                        error(
                                "PAYLOAD_TOO_LARGE",
                                exception.getMessage(),
                                List.of()
                        )
                );
    }

    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateResource(
            DuplicateResourceException exception
    ) {

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(
                        error(
                                "RESOURCE_CONFLICT",
                                exception.getMessage(),
                                List.of()
                        )
                );
    }

    /*
     * ============================================================
     * 409 - INVALID STATUS TRANSITION
     * ============================================================
     */

    @ExceptionHandler(InvalidStatusTransitionException.class)
    public ResponseEntity<ErrorResponse> handleStatusTransition(
            InvalidStatusTransitionException exception
    ) {

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(
                        error(
                                "INVALID_STATUS_TRANSITION",
                                exception.getMessage(),
                                List.of()
                        )
                );
    }

    /*
     * ============================================================
     * 400 - DTO VALIDATION
     * ============================================================
     */

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(
            MethodArgumentNotValidException exception
    ) {

        List<String> details =
                exception
                        .getBindingResult()
                        .getFieldErrors()
                        .stream()
                        .map(fieldError ->
                                fieldError.getField()
                                        + ": "
                                        + fieldError.getDefaultMessage()
                        )
                        .sorted()
                        .toList();

        return ResponseEntity
                .badRequest()
                .body(
                        error(
                                "VALIDATION_ERROR",
                                "Request validation failed",
                                details
                        )
                );
    }

    /*
     * ============================================================
     * 400 - INVALID PATH / QUERY PARAMETER TYPE
     * ============================================================
     */

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErrorResponse> handleTypeMismatch(
            MethodArgumentTypeMismatchException exception
    ) {

        String message =
                "Invalid value for parameter: "
                        + exception.getName();

        return ResponseEntity
                .badRequest()
                .body(
                        error(
                                "INVALID_PARAMETER",
                                message,
                                List.of()
                        )
                );
    }

    /*
     * ============================================================
     * 400 - JSON / ENUM / DATE / OTHER FORMAT ERRORS
     * ============================================================
     */

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleMalformedJson(
            HttpMessageNotReadableException exception
    ) {

        Throwable cause = exception;

        /*
         * Walk through the complete exception chain.
         *
         * Jackson/Spring may wrap the real exception several
         * levels deep.
         */
        while (cause != null) {

            /*
             * ====================================================
             * INVALID ENUM / INVALID FORMAT
             * ====================================================
             */

            if (cause instanceof InvalidFormatException invalidFormat) {

                String field =
                        extractFieldName(
                                invalidFormat
                        );

                /*
                 * Invalid enum
                 */

                if (invalidFormat.getTargetType() != null
                        && invalidFormat
                        .getTargetType()
                        .isEnum()) {

                    return ResponseEntity
                            .badRequest()
                            .body(
                                    error(
                                            "INVALID_ENUM",
                                            "Invalid value for "
                                                    + field
                                                    + ": "
                                                    + invalidFormat
                                                    .getValue(),
                                            List.of()
                                    )
                            );
                }

                /*
                 * Other invalid formats
                 */

                return ResponseEntity
                        .badRequest()
                        .body(
                                error(
                                        "INVALID_PARAMETER",
                                        "Invalid value for "
                                                + field
                                                + ": "
                                                + invalidFormat
                                                .getValue(),
                                        List.of()
                                )
                        );
            }

            /*
             * ====================================================
             * INVALID DATE / TIME
             * ====================================================
             */

            if (cause instanceof DateTimeParseException) {

                String field =
                        extractFieldName(
                                exception
                        );

                return ResponseEntity
                        .badRequest()
                        .body(
                                error(
                                        "INVALID_PARAMETER",
                                        "Invalid date/time value for "
                                                + field,
                                        List.of()
                                )
                        );
            }

            cause = cause.getCause();
        }

        /*
         * ========================================================
         * ACTUAL MALFORMED JSON
         * ========================================================
         */

        return ResponseEntity
                .badRequest()
                .body(
                        error(
                                "MALFORMED_REQUEST",
                                "Request body is missing or malformed",
                                List.of()
                        )
                );
    }

    /*
     * ============================================================
     * EXTRACT FIELD NAME FROM JSON MAPPING EXCEPTION
     * ============================================================
     */

    private String extractFieldName(
            JsonMappingException exception
    ) {

        return exception
                .getPath()
                .stream()
                .findFirst()
                .map(
                        JsonMappingException.Reference::getFieldName
                )
                .orElse("field");
    }

    /*
     * ============================================================
     * EXTRACT FIELD NAME FROM HTTP MESSAGE EXCEPTION
     * ============================================================
     */

    private String extractFieldName(
            HttpMessageNotReadableException exception
    ) {

        Throwable cause = exception;

        while (cause != null) {

            if (cause instanceof JsonMappingException mappingException) {

                return extractFieldName(
                        mappingException
                );
            }

            cause = cause.getCause();
        }

        return "field";
    }

    /*
     * ============================================================
     * 405 - UNSUPPORTED HTTP METHOD
     * ============================================================
     *
     * Without this, an unmapped method/path combination (e.g. a bare GET
     * on a resource that only supports POST and GET/{id}) fell through to
     * the generic Exception.class handler below and came back as a 500,
     * which looks like a server bug rather than the client simply hitting
     * a route that doesn't exist for that verb.
     */

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException exception
    ) {

        return ResponseEntity
                .status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(
                        error(
                                "METHOD_NOT_ALLOWED",
                                exception.getMessage(),
                                List.of()
                        )
                );
    }

    /*
     * ============================================================
     * 404 / 415 / 400 - REQUESTS SPRING MVC ITSELF REJECTS
     * ============================================================
     *
     * Same reason as the 405 handler above: without these, an unknown
     * path (NoResourceFoundException), a wrong Content-Type, or a missing
     * required query parameter fell through to the generic handler below
     * and came back as a 500.
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoResource(
            NoResourceFoundException exception
    ) {
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(
                        error(
                                "NOT_FOUND",
                                "No endpoint matches " + exception.getHttpMethod() + " /" + exception.getResourcePath(),
                                List.of()
                        )
                );
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleUnsupportedMediaType(
            HttpMediaTypeNotSupportedException exception
    ) {
        return ResponseEntity
                .status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(
                        error(
                                "UNSUPPORTED_MEDIA_TYPE",
                                "Content-Type must be application/json",
                                List.of()
                        )
                );
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ErrorResponse> handleMissingParameter(
            MissingServletRequestParameterException exception
    ) {
        return ResponseEntity
                .badRequest()
                .body(
                        error(
                                "INVALID_PARAMETER",
                                "Missing required parameter: " + exception.getParameterName(),
                                List.of()
                        )
                );
    }

    /*
     * ============================================================
     * 400 - BUSINESS INPUT ERROR
     * ============================================================
     */

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleBadRequest(
            IllegalArgumentException exception
    ) {

        String message =
                exception.getMessage();

        if (message == null || message.isBlank()) {
            message = "Invalid request";
        }

        return ResponseEntity
                .badRequest()
                .body(
                        error(
                                "BAD_REQUEST",
                                message,
                                List.of()
                        )
                );
    }

    /*
     * ============================================================
     * 409 - DATABASE CONSTRAINT VIOLATION
     * ============================================================
     */

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrity(
            DataIntegrityViolationException exception
    ) {

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(
                        error(
                                "DATA_CONFLICT",
                                "The request conflicts with existing data",
                                List.of()
                        )
                );
    }

    /*
     * ============================================================
     * 409 - CONCURRENT MODIFICATION (optimistic locking)
     * ============================================================
     *
     * Thrown when a saveAndFlush/flush detects that the row's version no
     * longer matches what this request read - another request updated the
     * same alert/incident in between. Before Alert.version/Incident.version
     * existed, this raced silently: both requests returned 200, one of them
     * describing a status that never actually persisted, and the audit log
     * recorded both transitions as if each had taken effect (confirmed
     * live). The client should reload the resource and retry.
     */

    @ExceptionHandler(ObjectOptimisticLockingFailureException.class)
    public ResponseEntity<ErrorResponse> handleConcurrentModification(
            ObjectOptimisticLockingFailureException exception
    ) {

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(
                        error(
                                "CONCURRENT_MODIFICATION",
                                "This resource was modified by another request. Reload and try again.",
                                List.of()
                        )
                );
    }

    /*
     * ============================================================
     * 503 - AI PROVIDER UNAVAILABLE
     * ============================================================
     *
     * The AI analyst-assistance layer (Phase 6) failing must never look
     * like the underlying incident/alert data is broken, and must never
     * leak the provider's raw exception message to the client - the real
     * cause is logged here, server-side only.
     */

    @ExceptionHandler(AiProviderUnavailableException.class)
    public ResponseEntity<ErrorResponse> handleAiProviderUnavailable(
            AiProviderUnavailableException exception
    ) {

        logger.warn(
                "AI provider unavailable requestId={} reason={}",
                requestId(),
                exception.getCause() == null ? exception.getMessage() : exception.getCause().getMessage(),
                exception
        );

        return ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(
                        error(
                                "AI_PROVIDER_UNAVAILABLE",
                                "The AI analyst-assistance service is currently unavailable. Please try again later.",
                                List.of()
                        )
                );
    }

    /*
     * ============================================================
     * 500 - UNEXPECTED ERROR
     * ============================================================
     */

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(
            Exception exception
    ) {

        /*
         * Previously this handler returned a generic 500 without logging
         * anything, so an unexpected bug anywhere in the application
         * produced an undiagnosable error with zero server-side trace.
         */
        logger.error(
                "Unhandled exception while processing request requestId={}",
                requestId(),
                exception
        );

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(
                        error(
                                "INTERNAL_ERROR",
                                "An unexpected error occurred",
                                List.of()
                        )
                );
    }
}