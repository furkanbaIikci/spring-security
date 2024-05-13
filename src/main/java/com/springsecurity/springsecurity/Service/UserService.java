package com.springsecurity.springsecurity.Service;

import com.springsecurity.springsecurity.DTO.Request.UserSaveRequest;
import com.springsecurity.springsecurity.Entity.Role;
import com.springsecurity.springsecurity.Entity.User;
import com.springsecurity.springsecurity.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public ResponseEntity<User> getUserById(Long id) {
        return ResponseEntity.ok(userRepository.findById(id).orElse(null));
    }

    public ResponseEntity<User> getUserByUsername(String username) {
        return ResponseEntity.ok(userRepository.findByUsername(username));
    }

    public ResponseEntity<String> saveUser(UserSaveRequest req) {
        User user = User.builder()
                .username(req.username())
                .password(req.password())
                .name(req.name())
                .surname(req.surname())
                .password(passwordEncoder.encode(req.password()))
                .role(Role.USER)
                .build();

        userRepository.save(user);

        return ResponseEntity.ok("The user has been registered successfully.");
    }

    public ResponseEntity<String> saveAdmin(UserSaveRequest req){
        User user = User.builder()
                .username(req.username())
                .password(req.password())
                .name(req.name())
                .surname(req.surname())
                .password(req.password())
                .role(Role.ADMIN)
                .build();

        userRepository.save(user);

        return ResponseEntity.ok("The admin has been registered successfully.");
    }
}
