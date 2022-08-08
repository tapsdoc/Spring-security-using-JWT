package com.jwt.supportportal.service;

import com.jwt.supportportal.exception.EmailExistException;
import com.jwt.supportportal.exception.EmailNotFoundException;
import com.jwt.supportportal.exception.UserNotFoundException;
import com.jwt.supportportal.exception.UsernameExistException;
import com.jwt.supportportal.model.Users;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {

    Users register(String firstName, String lastName, String username, String email)
            throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException;
    List<Users> getUsers();
    Users findByUsername(String username);
    Users findUserByEmail(String email);
    Users addNewUser(
            String firstName,
            String lastName,
            String username,
            String email,
            String role,
            boolean isNonLocked,
            boolean isActive,
            MultipartFile profileImage
    ) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;
    Users updateUser(
            String currentUsername,
            String newFirstName,
            String newLastName,
            String newUsername,
            String newEmail,
            String role,
            boolean isNonLocked,
            boolean isActive,
            MultipartFile profileImage
    ) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;
    void deleteUser(Long id);
    void resetPassword(String email) throws EmailNotFoundException, MessagingException;
    Users updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;

}
