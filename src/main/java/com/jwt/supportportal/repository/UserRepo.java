package com.jwt.supportportal.repository;

import com.jwt.supportportal.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<Users, Long> {

    Users findAppUserByUsername(String username);
    Users findAppUserByEmail(String email);
}
