package com.newzen.security.config.auth.imagecode;

import java.time.LocalDateTime;

public class CaptchImageVO {

    private String code;

    private LocalDateTime expireTime;

    public CaptchImageVO(String code, int expireAfterSeconds) {
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireAfterSeconds);
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expireTime);
    }

    public String getCode() {
        return this.code;
    }
}
