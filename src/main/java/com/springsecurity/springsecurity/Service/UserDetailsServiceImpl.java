package com.springsecurity.springsecurity.Service;

import com.springsecurity.springsecurity.Entity.User;
import com.springsecurity.springsecurity.Repository.UserRepository;
import com.springsecurity.springsecurity.Security.JwtUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);

        return JwtUserDetails.create(user);
    }

    public UserDetails loadUserById(Long id ){
        User user = userRepository.findById(id).get();

        return JwtUserDetails.create(user);
    }
}
