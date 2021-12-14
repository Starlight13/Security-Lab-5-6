package com.romanishuna.security.lab.wrapper;

import com.romanishuna.security.lab.model.User;
import com.romanishuna.security.lab.model.UserRegistration;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {
    private final ModelMapper modelMapper;

    public UserMapper() {
        modelMapper = new ModelMapper();
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);
    }

    public User dtoToEntity(UserRegistration userDTO) {
        return modelMapper.map(userDTO, User.class);
    }
}
