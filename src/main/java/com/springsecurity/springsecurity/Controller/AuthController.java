package com.springsecurity.springsecurity.Controller;

import com.springsecurity.springsecurity.DTO.Request.LoginRequest;
import com.springsecurity.springsecurity.DTO.Request.RefreshTokenRequest;
import com.springsecurity.springsecurity.DTO.Response.AuthResponse;
import com.springsecurity.springsecurity.DTO.Response.LoginResponse;
import com.springsecurity.springsecurity.Service.AuthService;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest req){
        return authService.login(req);
    }

//    @PostMapping("/refresh")
//    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest request){
//        return authService.refresh(request);
//    }
}
