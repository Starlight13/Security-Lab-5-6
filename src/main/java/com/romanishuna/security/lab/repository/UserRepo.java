package com.romanishuna.security.lab.repository;

import com.romanishuna.security.lab.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface UserRepo extends JpaRepository<User, UUID> {

    User findUserByEmail(String email);
}

