package com.jwt.supportportal.controller;

import com.jwt.supportportal.exception.*;
import com.jwt.supportportal.model.HttpResponse;
import com.jwt.supportportal.model.UserPrincipal;
import com.jwt.supportportal.model.Users;
import com.jwt.supportportal.service.UserService;
import com.jwt.supportportal.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import javax.validation.Path;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static com.jwt.supportportal.constant.FileConstant.*;
import static com.jwt.supportportal.constant.SecurityConstant.JWT_TOKEN_HEADER;
import static org.springframework.http.HttpStatus.NO_CONTENT;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.IMAGE_JPEG_VALUE;

@RestController
@RequestMapping(path = {"/", "/user"})
@RequiredArgsConstructor
public class UserController extends ExceptionHandling {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;

    @PostMapping("/register")
    public ResponseEntity<Users> register(@RequestBody Users user)
            throws EmailExistException, UserNotFoundException, UsernameExistException, MessagingException {
        Users newUser = userService.register(
                user.getFirstName(),
                user.getLastName(),
                user.getUsername(),
                user.getEmail());
        return new ResponseEntity<>(newUser, OK);
    }

    @PostMapping("/login")
    public ResponseEntity<Users> login(@RequestBody Users user) {

        authenticate(user.getUsername(), user.getPassword());
        Users loginUser = userService.findByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        return new ResponseEntity<>(loginUser, jwtHeader, OK);
    }

    @PostMapping("/add")
    public ResponseEntity<Users> addNewUser(
            @RequestParam("firstName") String firstName,
            @RequestParam("lastName") String lastName,
            @RequestParam("username") String username,
            @RequestParam("email") String email,
            @RequestParam("role") String role,
            @RequestParam("isActive") String isActive,
            @RequestParam("isNonLocked") String isNonLocked,
            @RequestParam(value = "profileImage", required = false) MultipartFile profileImage
    ) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {

        Users newUser = userService.addNewUser(
                firstName,
                lastName,
                username,
                email,
                role,
                Boolean.parseBoolean(isNonLocked),
                Boolean.parseBoolean(isActive),
                profileImage
        );
        return new ResponseEntity<>(newUser, OK);
    }

    @PutMapping("/update")
    public ResponseEntity<Users> updateUser(
            @RequestParam("currentUsername") String currentUsername,
            @RequestParam("firstName") String firstName,
            @RequestParam("lastName") String lastName,
            @RequestParam("username") String username,
            @RequestParam("email") String email,
            @RequestParam("role") String role,
            @RequestParam("isActive") String isActive,
            @RequestParam("isNonLocked") String isNonLocked,
            @RequestParam(value = "profileImage", required = false) MultipartFile profileImage
    ) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {

        Users updatedUser = userService.updateUser(
                currentUsername,
                firstName,
                lastName,
                username,
                email,
                role,
                Boolean.parseBoolean(isNonLocked),
                Boolean.parseBoolean(isActive),
                profileImage
        );
        return new ResponseEntity<>(updatedUser, OK);
    }

    @GetMapping("/find/{username}")
    public ResponseEntity<Users> getUser(@PathVariable("username") String username){
        Users user = userService.findByUsername(username);
        return new ResponseEntity<>(user, OK);
    }

    @GetMapping("/list")
    public ResponseEntity<List<Users>> getAllUsers(){
        List<Users> users = userService.getUsers();
        return new ResponseEntity<>(users, OK);
    }

    @GetMapping("/reset-password/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email)
            throws EmailNotFoundException, MessagingException {
        userService.resetPassword(email);
        return response(OK, "An email with new password was sent to " + email);
    }

    @PutMapping("/update-profile-image")
    public ResponseEntity<Users> updateProfileImage(
            @RequestParam("username") String username,
            @RequestParam(value = "profileImage") MultipartFile profileImage
    ) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {

        Users user = userService.updateProfileImage(username, profileImage);
        return new ResponseEntity<>(user, OK);
    }

    @GetMapping(value = "/image/{username}/{filename}", produces = IMAGE_JPEG_VALUE)
    public byte[] getProfileImage(
            @PathVariable String username,
            @PathVariable String filename
    ) throws IOException {
        return Files.readAllBytes(Paths.get(USER_FOLDER + username + FORWARD_SLASH + filename));
    }

    @GetMapping(value = "/image/profile/{username}", produces = IMAGE_JPEG_VALUE)
    public byte[] getTempProfileImage(@PathVariable String username) throws IOException {

        URL url = new URL(TEMP_PROFILE_IMAGE_BASE_URL + username);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (InputStream inputStream = url.openStream()){
            int bytesRead;
            byte[] chunk = new byte[1024];
            while ((bytesRead = inputStream.read(chunk)) > 0){
                outputStream.write(chunk, 0, bytesRead);
            }
        }
        return outputStream.toByteArray();
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAnyAuthority('user:delete')")
    public ResponseEntity<HttpResponse> deleteUser(@PathVariable("id") Long id){
        userService.deleteUser(id);
        return response(NO_CONTENT, "User deleted successfully");
    }
    private ResponseEntity<HttpResponse> response(HttpStatus httpStatus, String message) {
        HttpResponse body = new HttpResponse(
                httpStatus.value(),
                httpStatus,
                httpStatus.getReasonPhrase().toUpperCase(),
                message
        );
        return new ResponseEntity<>(body, httpStatus);
    }

    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, tokenProvider.generateJwtToken(userPrincipal));
        return headers;
    }

    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
