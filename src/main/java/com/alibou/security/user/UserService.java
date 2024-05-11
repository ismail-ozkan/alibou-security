package com.alibou.security.user;

import java.util.List;

public interface UserService {

    User getByEmail(String email);

    User getByUserId(Integer userId);

    User save(User user);

    List<User> getAll();

}
