import { LoginRequest, RefreshTokenRequest, RegisterRequest, ValidateRequest } from '../proto-buffers/auth.pb';
export declare enum Gender {
    MALE = "MALE",
    FEMALE = "FEMALE",
    OTHER = "OTHER"
}
export declare class LoginRequestDto implements LoginRequest {
    email: string;
    password: string;
}
export declare class RegisterRequestDto implements RegisterRequest {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    gender: string;
}
export declare class ValidateRequestDto implements ValidateRequest {
    token: string;
}
export declare class RefreshTokenRequestDto implements RefreshTokenRequest {
    refreshToken: string;
    userId: any;
}
