package co.istad.app.service;

import co.istad.app.dto.LogInDto;

public interface AuthService {

    String login(LogInDto logInDto);

}
