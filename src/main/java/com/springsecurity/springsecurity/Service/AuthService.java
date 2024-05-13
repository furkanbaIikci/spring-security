package com.springsecurity.springsecurity.Service;

import com.springsecurity.springsecurity.DTO.Request.LoginRequest;
import com.springsecurity.springsecurity.DTO.Request.RefreshTokenRequest;
import com.springsecurity.springsecurity.DTO.Response.AuthResponse;
import com.springsecurity.springsecurity.Entity.RefreshToken;
import com.springsecurity.springsecurity.Entity.User;
import com.springsecurity.springsecurity.Repository.RefreshTokenRepository;
import com.springsecurity.springsecurity.Repository.UserRepository;
import com.springsecurity.springsecurity.Security.JwtTokenProvider;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${refresh.token.expires.in}")
    Long expireSeconds;

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;

    public ResponseEntity<AuthResponse> login(LoginRequest loginRequest) {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(loginRequest.username(),
                loginRequest.password());
        System.out.println(authToken.getCredentials() +  authToken.getName() + authToken.getPrincipal());
        Authentication auth = authenticationManager.authenticate(authToken);
        SecurityContextHolder.getContext().setAuthentication(auth);
        System.out.println(auth);
        String jwtToken = jwtTokenProvider.generateJwtToken(auth);
        System.out.println(jwtToken);
        User user = userRepository.findByUsername(loginRequest.username());

        if (user == null) {
            return ResponseEntity.notFound().build();
        }

        RefreshToken refreshToken = refreshTokenRepository.findByUserId(user.getId());

        if(refreshToken == null){
            createRefreshToken(user);
        }
        Cookie cookie = new Cookie("timestamp", new Date().getTime()+";HttpOnly");

        AuthResponse authResponse = new AuthResponse(user.getId(), jwtToken);

        return ResponseEntity.ok(authResponse);
    }

    public String createRefreshToken(User user) {
        RefreshToken token = refreshTokenRepository.findByUserId(user.getId());
        if(token == null) {
            token =	new RefreshToken();
            token.setUser(user);
            token.setToken(UUID.randomUUID().toString());
            token.setExpiryDate(Date.from(Instant.now().plusSeconds(expireSeconds)));
            refreshTokenRepository.save(token);
        }
        return token.getToken();
    }

    public boolean isRefreshExpired(RefreshToken token) {
        return token.getExpiryDate().before(new Date());
    }

    public RefreshToken getByUser(Long userId) {
        return refreshTokenRepository.findByUserId(userId);
    }

//    public ResponseEntity<AuthResponse> refresh(RefreshTokenRequest request) {
//        AuthResponse response;
//        RefreshToken token = refreshTokenRepository.findByUserId(request.userId());
//        if (token.getToken().equals(request.token()) && !isRefreshExpired(token)) {
//
//            User user = token.getUser();
//            String jwtToken = jwtTokenProvider.generateJwtTokenByUserId(user.getId());
//            //response = new AuthResponse("token successfully refreshed.", user.getId(), jwtToken);
//
//            return new ResponseEntity<>(response, HttpStatus.OK);
//        } else {
//            //response = new AuthResponse("refresh token is not valid.", null, null);
//            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
//        }
//    }
}
