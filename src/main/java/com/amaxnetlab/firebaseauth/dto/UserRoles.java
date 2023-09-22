package com.amaxnetlab.firebaseauth.dto;

import com.amaxnetlab.firebaseauth.enums.Roles;
import lombok.Data;

@Data
public class UserRoles {
    private Roles role;
    private String unitId;
}
