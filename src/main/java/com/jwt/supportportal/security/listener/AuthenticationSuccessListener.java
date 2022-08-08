package com.jwt.supportportal.security.listener;


import com.jwt.supportportal.model.Users;
import com.jwt.supportportal.service.LoginAttemptService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationSuccessListener {

    private LoginAttemptService loginAttemptService;

    public void onAuthenticationSuccess(AuthenticationSuccessEvent event){
        Object principal = event.getAuthentication().getPrincipal();
        if (principal instanceof Users){
            Users user = (Users) event.getAuthentication().getPrincipal();
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
        }
    }
}
