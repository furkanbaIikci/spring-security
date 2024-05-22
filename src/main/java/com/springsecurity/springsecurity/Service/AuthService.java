package com.springsecurity.springsecurity.Service;

import com.springsecurity.springsecurity.DTO.Request.LoginRequest;
import com.springsecurity.springsecurity.DTO.Request.RefreshTokenRequest;
import com.springsecurity.springsecurity.DTO.Response.AuthResponse;
import com.springsecurity.springsecurity.Entity.RefreshToken;
import com.springsecurity.springsecurity.Entity.User;
import com.springsecurity.springsecurity.Repository.RefreshTokenRepository;
import com.springsecurity.springsecurity.Repository.UserRepository;
import com.springsecurity.springsecurity.Security.JwtTokenProvider;
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

        User user = userRepository.findByUsername(loginRequest.username());

        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(loginRequest.username(),
                loginRequest.password());
        Authentication auth = authenticationManager.authenticate(authToken);
        SecurityContextHolder.getContext().setAuthentication(auth);
        String jwtToken = jwtTokenProvider.generateJwtToken(auth);


        RefreshToken refreshToken = refreshTokenRepository.findByUserId(user.getId());
        String newRefreshToken;
        if (refreshToken == null || refreshToken.getToken() == null) {
            newRefreshToken = createRefreshToken(user);
        }else{
            newRefreshToken = refreshToken.getToken();
        }

        AuthResponse authResponse = new AuthResponse(user.getId(), jwtToken, newRefreshToken);

        return ResponseEntity.ok(authResponse);
    }

    public String createRefreshToken(User user) {
        RefreshToken token = refreshTokenRepository.findByUserId(user.getId());
        if (token == null) {
            token = new RefreshToken();
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

    public ResponseEntity<AuthResponse> refresh(RefreshTokenRequest request) {
        AuthResponse response;
        RefreshToken refreshToken = refreshTokenRepository.findByUserId(request.userId());
        if (refreshToken != null && refreshToken.getToken().equals(request.refreshToken()) && !isRefreshExpired(refreshToken)) {

            User user = refreshToken.getUser();
            String jwtToken = jwtTokenProvider.generateJwtTokenByUserId(user.getId());
            response = new AuthResponse(user.getId(), jwtToken, refreshToken.getToken());

            return new ResponseEntity<>(response, HttpStatus.OK);
        } else {
            //response = new AuthResponse();
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }
}
