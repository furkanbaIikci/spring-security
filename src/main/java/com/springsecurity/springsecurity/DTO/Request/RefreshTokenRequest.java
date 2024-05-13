package com.springsecurity.springsecurity.DTO.Request;

public record RefreshTokenRequest(Long userId, String token) {
}
