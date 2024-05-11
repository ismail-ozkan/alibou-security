package com.alibou.security;

import com.alibou.security.user.Role;
import com.alibou.security.user.User;

public class Test {

    @org.junit.jupiter.api.Test
    public void jwtTest(){
        User user = new User(12,"ismail", "ozkan","ismail@mail.com","asd123", Role.USER);

        System.out.println(user);


    }


}
