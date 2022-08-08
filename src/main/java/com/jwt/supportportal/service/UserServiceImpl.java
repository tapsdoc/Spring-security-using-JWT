package com.jwt.supportportal.service;

import com.jwt.supportportal.enums.Role;
import com.jwt.supportportal.exception.EmailExistException;
import com.jwt.supportportal.exception.EmailNotFoundException;
import com.jwt.supportportal.exception.UserNotFoundException;
import com.jwt.supportportal.exception.UsernameExistException;
import com.jwt.supportportal.model.Users;
import com.jwt.supportportal.model.UserPrincipal;
import com.jwt.supportportal.repository.UserRepo;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.mail.MessagingException;
import javax.transaction.Transactional;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static com.jwt.supportportal.constant.FileConstant.*;
import static com.jwt.supportportal.enums.Role.ROLE_USER;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.apache.commons.lang3.StringUtils.EMPTY;

@Service
@Transactional
@Qualifier("userDetailsService")
public class UserServiceImpl implements UserService, UserDetailsService {

    public static final UsernameExistException USERNAME_EXIST_EXCEPTION = new UsernameExistException("Username already exists!");
    private final UserRepo userRepo;
    private final Logger LOGGER = LoggerFactory.getLogger(getClass());
    private final BCryptPasswordEncoder passwordEncoder;
    private final LoginAttemptService loginAttemptService;
    private final EmailService emailService;

    @Autowired
    public UserServiceImpl(
            UserRepo userRepo,
            BCryptPasswordEncoder bCryptPasswordEncoder,
            LoginAttemptService loginAttemptService, EmailService emailService){

        this.userRepo = userRepo;
        this.passwordEncoder = bCryptPasswordEncoder;
        this.loginAttemptService = loginAttemptService;
        this.emailService = emailService;
    }
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = userRepo.findAppUserByUsername(username);
        if (user == null){
            LOGGER.error("Users not found by username: " + username);
            throw new UsernameNotFoundException("Users not found by username: " + username);
        } else {
            validateLoginAttempt(user);
            user.setLastLoginDateDisplay(user.getLastLoginDate());
            user.setLastLoginDate(new Date());
            userRepo.save(user);
            UserPrincipal userPrincipal = new UserPrincipal(user);
            LOGGER.error("Returning user by username: " + username);
            return userPrincipal;
        }
    }

    private void validateLoginAttempt(Users user){
        if (user.isNotLocked()){
            try {
                user.setNotLocked(!loginAttemptService.hasExceededMaxAttempts(user.getUsername()));
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        } else {
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
        }
    }

    @Override
    public Users register(String firstName, String lastName, String username, String email)
            throws UserNotFoundException, EmailExistException, UsernameExistException {

        validateNewUsernameAndEmail(EMPTY, username, email);
        Users user = new Users();
        user.setUserId(generateUserId());
        String password = generatePassword();
        String encodedPassword = encodePassword(password);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUsername(username);
        user.setEmail(email);
        user.setJoinDate(new Date());
        user.setPassword(encodePassword(password));
        user.setActive(true);
        user.setNotLocked(true);
        user.setRole(ROLE_USER.name());
        user.setAuthorities(ROLE_USER.getAuthorities());
        user.setProfileImageUrl(getTemporaryProfileImage(username));
        userRepo.save(user);
        LOGGER.info("New user password: " + password);
        return user;
    }

    private String generateUserId() {
        return RandomStringUtils.randomNumeric(10);
    }

    private String generatePassword() {
        return RandomStringUtils.randomAlphanumeric(10);
    }

    private String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

    private Users validateNewUsernameAndEmail(String currentUsername, String newUsername, String newEmail)
            throws UsernameExistException, EmailExistException, UserNotFoundException {

        Users userByNewUsername = findByUsername(newUsername);
        Users userByNewEmail = findUserByEmail(newEmail);
        if (StringUtils.isNotBlank(currentUsername)){
            Users currentUser = findByUsername(currentUsername);
            if (currentUser == null){
                throw new UserNotFoundException("No user found by username " + currentUsername);
            }

            if (userByNewUsername != null && !currentUser.getId().equals(userByNewUsername.getId())){
                throw new UsernameExistException("Username already exist!");
            }

            if (userByNewEmail != null && !currentUser.getId().equals(userByNewEmail.getId())){
                throw new EmailExistException("Email already exist!");
            }
            return currentUser;
        } else {
            if (userByNewUsername != null){
                throw USERNAME_EXIST_EXCEPTION;
            }
            if (userByNewEmail != null){
                throw new EmailExistException("Email already exist!");
            }
        }
        return null;
    }

    @Override
    public List<Users> getUsers() {
        return userRepo.findAll();
    }

    @Override
    public Users findByUsername(String username) {
        return userRepo.findAppUserByUsername(username);
    }

    @Override
    public Users findUserByEmail(String email) {
        return userRepo.findAppUserByEmail(email);
    }

    @Override
    public Users addNewUser(
            String firstName,
            String lastName,
            String username,
            String email,
            String role,
            boolean isNonLocked,
            boolean isActive,
            MultipartFile profileImage
    ) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException {

        validateNewUsernameAndEmail(EMPTY, username, email);
        Users user = new Users();
        String password = generatePassword();
        user.setUserId(generateUserId());
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setJoinDate(new Date());
        user.setEmail(email);
        user.setUsername(username);
        user.setPassword(encodePassword(password));
        user.setActive(isActive);
        user.setNotLocked(isNonLocked);
        user.setRole(getRoleEnumName(role).name());
        user.setAuthorities(getRoleEnumName(role).getAuthorities());
        user.setProfileImageUrl(getTemporaryProfileImage(username));
        userRepo.save(user);
        saveProfileImage(user, profileImage);
        return user;
    }

    @Override
    public Users updateUser(
            String currentUsername,
            String newFirstName,
            String newLastName,
            String newUsername,
            String newEmail,
            String role,
            boolean isNonLocked,
            boolean isActive,
            MultipartFile profileImage
    ) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException {

        validateNewUsernameAndEmail(currentUsername, newUsername, newEmail);
        Users currentUser = new Users();
        currentUser.setFirstName(newFirstName);
        currentUser.setLastName(newLastName);
        currentUser.setEmail(newEmail);
        currentUser.setUsername(newUsername);
        currentUser.setActive(isActive);
        currentUser.setNotLocked(isNonLocked);
        currentUser.setRole(getRoleEnumName(role).name());
        userRepo.save(currentUser);
        saveProfileImage(currentUser, profileImage);
        return currentUser;
    }

    @Override
    public void deleteUser(Long id) {
        userRepo.deleteById(id);
    }

    @Override
    public void resetPassword(String email) throws EmailNotFoundException, MessagingException {
        Users user = userRepo.findAppUserByEmail(email);
        if (user == null){
            throw new EmailNotFoundException("No user found with the email address " + email);
        }
        String password = generatePassword();
        user.setPassword(encodePassword(password));
        userRepo.save(user);
        emailService.sendNewPasswordEmail(user.getFirstName(), password, user.getEmail());
    }

    @Override
    public Users updateProfileImage(String username, MultipartFile profileImage)
            throws UserNotFoundException, EmailExistException, UsernameExistException, IOException {

        Users user = validateNewUsernameAndEmail(username, null, null);
        saveProfileImage(user, profileImage);
        return user;
    }

    private void saveProfileImage(Users user, MultipartFile profileImage) throws IOException {
        if (profileImage != null){
            Path userFolder = Paths.get(USER_FOLDER + user.getUsername()).toAbsolutePath().normalize();
            if (!Files.exists(userFolder)){
                Files.createDirectories(userFolder);
                LOGGER.info(DIRECTORY_CREATED + userFolder);
            }
            Files.deleteIfExists(Paths.get(userFolder + user.getUsername() + DOT + JPG_EXTENSION));
            Files.copy(profileImage.getInputStream(),
                    userFolder.resolve(user.getUsername() + DOT + JPG_EXTENSION), REPLACE_EXISTING
            );
            user.setProfileImageUrl(setProfileImageUrl(user.getUsername()));
            userRepo.save(user);
            LOGGER.info(FILE_SAVED_IN_FILE_SYSTEM + profileImage.getOriginalFilename());

        }
    }

    private String setProfileImageUrl(String username) {
        return ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path(USER_IMAGE_PATH + username + FORWARD_SLASH + username + DOT + JPG_EXTENSION)
                .toUriString();
    }

    private Role getRoleEnumName(String role) {
        return Role.valueOf(role.toUpperCase());
    }

    private String getTemporaryProfileImage(String username) {
        return ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/user/image/profile/temp")
                .toUriString();
    }
}
