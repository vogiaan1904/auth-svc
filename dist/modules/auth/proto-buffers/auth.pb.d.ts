import { Observable } from "rxjs";
export declare const protobufPackage = "auth";
export interface RegisterRequest {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    gender: string;
}
export interface RegisterResponse {
    status: number;
    error: string[];
}
export interface LoginRequest {
    email: string;
    password: string;
}
export interface LoginResponse {
    status: number;
    error: string[];
    accessToken: string;
    refreshToken: string;
}
export interface RefreshTokenRequest {
    refreshToken: string;
    userId: string;
}
export interface RefreshTokenResponse {
    status: number;
    error: string[];
    accessToken: string;
    refreshToken: string;
}
export interface SendVerificationEmailRequest {
    email: string;
}
export interface SendVerificationEmailResponse {
    status: number;
    error: string[];
}
export interface ForgotPasswordRequest {
    email: string;
}
export interface ForgotPasswordResponse {
    status: number;
    error: string[];
}
export interface ResetPasswordRequest {
    token: string;
    password: string;
}
export interface ResetPasswordResponse {
    status: number;
    error: string[];
}
export interface ValidateRequest {
    token: string;
}
export interface ValidateResponse {
    status: number;
    error: string[];
    userId: string;
}
export declare const AUTH_PACKAGE_NAME = "auth";
export interface AuthServiceClient {
    register(request: RegisterRequest): Observable<RegisterResponse>;
    login(request: LoginRequest): Observable<LoginResponse>;
    validate(request: ValidateRequest): Observable<ValidateResponse>;
    refreshToken(request: RefreshTokenRequest): Observable<RefreshTokenResponse>;
    sendVerificationEmail(request: SendVerificationEmailRequest): Observable<SendVerificationEmailResponse>;
    forgotPassword(request: ForgotPasswordRequest): Observable<ForgotPasswordResponse>;
    resetPassword(request: ResetPasswordRequest): Observable<ResetPasswordResponse>;
}
export interface AuthServiceController {
    register(request: RegisterRequest): Promise<RegisterResponse> | Observable<RegisterResponse> | RegisterResponse;
    login(request: LoginRequest): Promise<LoginResponse> | Observable<LoginResponse> | LoginResponse;
    validate(request: ValidateRequest): Promise<ValidateResponse> | Observable<ValidateResponse> | ValidateResponse;
    refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> | Observable<RefreshTokenResponse> | RefreshTokenResponse;
    sendVerificationEmail(request: SendVerificationEmailRequest): Promise<SendVerificationEmailResponse> | Observable<SendVerificationEmailResponse> | SendVerificationEmailResponse;
    forgotPassword(request: ForgotPasswordRequest): Promise<ForgotPasswordResponse> | Observable<ForgotPasswordResponse> | ForgotPasswordResponse;
    resetPassword(request: ResetPasswordRequest): Promise<ResetPasswordResponse> | Observable<ResetPasswordResponse> | ResetPasswordResponse;
}
export declare function AuthServiceControllerMethods(): (constructor: Function) => void;
export declare const AUTH_SERVICE_NAME = "AuthService";
