package com.jwt.supportportal.security.listener;

import com.jwt.supportportal.service.LoginAttemptService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

import java.util.concurrent.ExecutionException;

@Component
@RequiredArgsConstructor
public class AuthenticationFailureListener {

    private LoginAttemptService loginAttemptService;

    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) throws ExecutionException {
        Object principal = event.getAuthentication().getPrincipal();
        if (principal instanceof String){
            String username = (String) event.getAuthentication().getPrincipal();
            loginAttemptService.addUserToLoginAttemptCache(username);
        }
    }
}
