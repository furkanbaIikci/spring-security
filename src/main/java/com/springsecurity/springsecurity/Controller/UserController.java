package com.springsecurity.springsecurity.Controller;

import com.springsecurity.springsecurity.DTO.Request.UserSaveRequest;
import com.springsecurity.springsecurity.Entity.User;
import com.springsecurity.springsecurity.Service.UserService;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/save")
    public ResponseEntity<String> saveUser(@RequestBody UserSaveRequest request){
        return userService.saveUser(request);
    }

    @GetMapping("/{id}")
    public ResponseEntity<User> getUserById(@PathVariable Long id){
        return userService.getUserById(id);
    }
    @GetMapping
    public String hello(){
        return "Hello World";
    }
}
