package com.amaxnetlab.firebaseauth.services;

import com.amaxnetlab.firebaseauth.entities.User;
import com.amaxnetlab.firebaseauth.enums.Roles;
import com.google.firebase.auth.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserManagementService {

    private final FirebaseAuth firebaseAuth;

    public UserRecord getUser(String uid) throws FirebaseAuthException {

        return firebaseAuth.getUser(uid);
    }

    public ListUsersPage listUsers() throws FirebaseAuthException {
        return firebaseAuth.listUsers(null);
    }

    public UserRecord createUser(User user) throws FirebaseAuthException {

        UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                .setEmail(user.getEmail())
                .setPassword(user.getPassword())
                .setEmailVerified(false)
                .setDisabled(false);

        UserRecord userRecord = firebaseAuth.createUser(request);

        setUserRole(userRecord.getUid(), Roles.ROLE_USER);

        return userRecord;
    }

    public void updateUser(String uid, User user) throws FirebaseAuthException {

        UserRecord.UpdateRequest request = new UserRecord.UpdateRequest(uid)
                .setPassword(user.getPassword())
                .setEmailVerified(false)
                .setDisabled(false);

        UserRecord userRecord = firebaseAuth.updateUser(request);

        setUserRole(userRecord.getUid(), Roles.ROLE_USER);

    }

    public void changeEmail(String uid, String email) throws FirebaseAuthException {
        firebaseAuth.updateUser(new UserRecord.UpdateRequest(uid).setEmail(email));
    }

    public void deleteUser(String uid) throws FirebaseAuthException {
        firebaseAuth.deleteUser(uid);
    }

    public void setUserRole(String uid, Roles role) throws FirebaseAuthException {
        firebaseAuth.setCustomUserClaims(uid, Collections.singletonMap("role", role.name()));
    }
}
