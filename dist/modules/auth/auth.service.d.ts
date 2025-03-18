import { OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ClientGrpc } from '@nestjs/microservices';
import { TokenService } from 'src/modules/token/token.service';
import { RegisterRequestDto, ValidateRequestDto } from './dto/auth-request.dto';
import { TokenPayload } from './interfaces/token.interface';
import { LoginRequest, LoginResponse, RefreshTokenRequest, RefreshTokenResponse, RegisterResponse, ValidateResponse } from './proto-buffers/auth.pb';
import { Cache } from 'cache-manager';
export declare class AuthService implements OnModuleInit {
    private userServiceClient;
    private readonly jwtService;
    private readonly configService;
    private readonly tokenService;
    private readonly cacheService;
    private readonly SALT_ROUND;
    private userService;
    private convertToSeconds;
    constructor(userServiceClient: ClientGrpc, jwtService: JwtService, configService: ConfigService, tokenService: TokenService, cacheService: Cache);
    onModuleInit(): void;
    register(dto: RegisterRequestDto): Promise<RegisterResponse>;
    login(dto: LoginRequest): Promise<LoginResponse>;
    validate({ token }: ValidateRequestDto): Promise<ValidateResponse>;
    storeRefreshToken(userId: string, refreshToken: string): Promise<void>;
    generateAccessToken(payload: TokenPayload): string;
    generateRefreshToken(payload: TokenPayload): string;
    refreshToken(payload: RefreshTokenRequest): Promise<RefreshTokenResponse>;
}
