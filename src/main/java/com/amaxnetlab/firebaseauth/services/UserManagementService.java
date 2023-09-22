package com.amaxnetlab.firebaseauth.services;

import com.amaxnetlab.firebaseauth.entities.User;
import com.amaxnetlab.firebaseauth.dto.UserRoles;
import com.amaxnetlab.firebaseauth.enums.Roles;
import com.google.firebase.auth.*;
import com.google.firebase.internal.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserManagementService {

    private final FirebaseAuth firebaseAuth;

    public UserRecord getUser(String uid) throws FirebaseAuthException {

        return firebaseAuth.getUser(uid);
    }

    public ListUsersPage listUsers(@Nullable String pageToken, int maxResults) throws FirebaseAuthException {
        return firebaseAuth.listUsers(pageToken, maxResults);
    }

    public UserRecord createUser(User user) throws FirebaseAuthException {

        UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                .setEmail(user.getEmail())
                .setPassword(user.getPassword())
                .setEmailVerified(false)
                .setDisabled(false);

        UserRecord userRecord = firebaseAuth.createUser(request);

        UserRoles userRoles = new UserRoles();
        userRoles.setRole(Roles.ROLE_USER);
        userRoles.setUnitId(null);

        setUserRole(userRecord.getUid(), userRoles);

        return userRecord;
    }

    public void updateUser(String uid, User user) throws FirebaseAuthException {

        UserRecord.UpdateRequest request = new UserRecord.UpdateRequest(uid)
                .setPassword(user.getPassword())
                .setEmailVerified(false)
                .setDisabled(false);

        UserRecord userRecord = firebaseAuth.updateUser(request);

        UserRoles userRoles = new UserRoles();
        userRoles.setRole(Roles.ROLE_USER);
        userRoles.setUnitId(null);

        setUserRole(userRecord.getUid(), userRoles);

    }

    public void changeEmail(String uid, String email) throws FirebaseAuthException {
        firebaseAuth.updateUser(new UserRecord.UpdateRequest(uid).setEmail(email));
    }

    public void deleteUser(String uid) throws FirebaseAuthException {
        firebaseAuth.deleteUser(uid);
    }

    public void setUserRole(String uid, UserRoles userRoles) throws FirebaseAuthException {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", userRoles.getRole().toString());
        claims.put("unitId", userRoles.getUnitId());

        firebaseAuth.setCustomUserClaims(uid, claims);
    }
}
