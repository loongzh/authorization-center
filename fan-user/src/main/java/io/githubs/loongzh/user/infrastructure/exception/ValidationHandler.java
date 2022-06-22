package io.githubs.loongzh.user.infrastructure.exception;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.support.WebExchangeBindException;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author fan
 * @date 2022年06月22日 20:22
 */
@ControllerAdvice
public class ValidationHandler {

    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<List<ValidationErrorInfo>> handleException(WebExchangeBindException e) {
        List<ValidationErrorInfo> errors = e.getBindingResult()
                .getAllErrors()
                .stream()
                .map(error->
                    new ValidationErrorInfo()
                            .setMessage( error.getDefaultMessage())
                            .setName(error.getObjectName())
                )
                .collect(Collectors.toList());
        return ResponseEntity.badRequest().body(errors);
    }
    @Getter
    @Setter
    @Accessors(chain = true)
    public static class ValidationErrorInfo{
        private String name;
        private String message;
    }
}
