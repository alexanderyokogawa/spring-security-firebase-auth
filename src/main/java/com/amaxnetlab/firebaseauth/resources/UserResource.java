package com.amaxnetlab.firebaseauth.resources;

import com.amaxnetlab.firebaseauth.entities.User;
import com.amaxnetlab.firebaseauth.dto.UserRoles;
import com.amaxnetlab.firebaseauth.services.UserManagementService;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.ListUsersPage;
import com.google.firebase.auth.UserRecord;
import com.google.firebase.internal.Nullable;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserResource {

    private final UserManagementService userManagementService;

    @GetMapping("/me")
//    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_USER')")
    public UserRecord me(@AuthenticationPrincipal Jwt jwt) throws FirebaseAuthException {
        return userManagementService.getUser(jwt.getSubject());
    }

    @GetMapping("/list")
    public ListUsersPage listUsers(@Nullable String pageToken, int maxResults) throws FirebaseAuthException {
        return userManagementService.listUsers(pageToken, maxResults);
    }

    @GetMapping("/get/{uid}")
    public UserRecord getUser(@PathVariable String uid, @AuthenticationPrincipal Jwt jwt) throws FirebaseAuthException {
        System.out.println(jwt.getClaims() + " - ROLE: " + jwt.getClaim("role"));
        return userManagementService.getUser(uid);
    }

    @PostMapping("/create")
    public UserRecord createUser(@RequestBody User user) throws FirebaseAuthException {
        return userManagementService.createUser(user);
    }

    @PutMapping("/update/{uid}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_USER')")
    public void updateUser(@PathVariable String uid, @RequestBody User user) throws FirebaseAuthException {
        userManagementService.updateUser(uid, user);
    }

    @PutMapping("/change email/{uid}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_USER')")
    public void changeEmail(@PathVariable String uid, @RequestBody String email) throws FirebaseAuthException {
        userManagementService.changeEmail(uid, email);
    }

    @PutMapping("/role/{uid}")
//    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public void setUserRole(@PathVariable String uid, @RequestBody UserRoles userRoles) throws FirebaseAuthException {
        userManagementService.setUserRole(uid, userRoles);
    }

    @GetMapping("/delete/{uid}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public void deleteUser(@PathVariable String uid) throws FirebaseAuthException {
        userManagementService.deleteUser(uid);
    }
}
