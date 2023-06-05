package co.istad.app.service;

import co.istad.app.dto.AuthDto;
import co.istad.app.dto.LogInDto;
import co.istad.app.dto.RefreshTokenDto;

public interface AuthService {

    AuthDto login(LogInDto logInDto);

    AuthDto refresh(RefreshTokenDto refreshTokenDto);

}
