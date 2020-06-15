package com.newzen.security.config.exception;

import lombok.Getter;
import lombok.Setter;

@Getter
public class CustomException extends RuntimeException {

    // 异常代码
    private int code;
    // 异常信息
    private String message;

    public CustomException(CustomExceptionType exceptionType, String message) {
        this.code = exceptionType.getCode();
        this.message = message;
    }

}
