import { HttpStatus, Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ClientGrpc, RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcryptjs';
import { firstValueFrom, throwError } from 'rxjs';
import { TokenService } from 'src/modules/token/token.service';
import {
  LoginRequestDto,
  RegisterRequestDto,
  Role,
  ValidateRequestDto,
} from './dto/auth-request.dto';
import { TokenPayload } from './interfaces/token.interface';
import {
  LoginRequest,
  LoginResponse,
  RefreshTokenRequest,
  RefreshTokenResponse,
  RegisterResponse,
  ValidateResponse,
} from './proto-buffers/auth.pb';
import {
  CreateUserRequest,
  CreateUserResponse,
  FindOneResponse,
  USER_SERVICE_NAME,
  UserServiceClient,
} from './proto-buffers/user.pb';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
@Injectable()
export class AuthService implements OnModuleInit {
  private readonly SALT_ROUND: number = 10;
  private userService: UserServiceClient;

  private convertToSeconds = (time: string): number => {
    const timeValue = parseInt(time.slice(0, -1), 10);
    const timeUnit = time.slice(-1);
    switch (timeUnit) {
      case 's': // seconds
        return timeValue;
      case 'm': // minutes
        return timeValue * 60;
      case 'h': // hours
        return timeValue * 60 * 60;
      case 'd': // days
        return timeValue * 24 * 60 * 60;
      default:
        throw new Error(
          "Invalid time format. Use 's', 'm', 'h' or 'd' (e.g., '30m' or '1h').",
        );
    }
  };

  constructor(
    @Inject(USER_SERVICE_NAME)
    private userServiceClient: ClientGrpc,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly tokenService: TokenService,
    @Inject(CACHE_MANAGER) private readonly cacheService: Cache,
  ) {}

  public onModuleInit(): void {
    this.userService =
      this.userServiceClient.getService<UserServiceClient>(USER_SERVICE_NAME);
  }

  async register(dto: RegisterRequestDto): Promise<RegisterResponse> {
    const { email, password, firstName, lastName, gender } = dto;

    const existingUserWithEmail: FindOneResponse = await firstValueFrom(
      this.userService.findOne({ email }),
    );

    if (existingUserWithEmail.status == HttpStatus.OK) {
      return {
        status: HttpStatus.CONFLICT,
        error: ['Email already exists'],
      };
    }

    const hashedPassword: string = await bcrypt.hash(password, this.SALT_ROUND);

    const createUserData: CreateUserRequest = {
      email: email,
      password: hashedPassword,
      firstName: firstName,
      lastName: lastName,
      gender: gender,
      role: Role.USER,
    };

    const response: CreateUserResponse = await firstValueFrom(
      this.userService.createUser(createUserData),
    );

    return {
      status: response.status,
      error: response.error,
    };
  }

  async login(dto: LoginRequest): Promise<LoginResponse> {
    const { email, password } = dto;
    const userResponse = await firstValueFrom(
      this.userService.findOne({ email }),
    );

    if (userResponse.status !== HttpStatus.OK) {
      return {
        status: HttpStatus.UNAUTHORIZED,
        error: ['User not found'],
        accessToken: null,
        refreshToken: null,
      };
    }

    const isValidPassword = await bcrypt.compare(
      password,
      userResponse.data.password,
    );
    if (!isValidPassword) {
      return {
        status: HttpStatus.BAD_REQUEST,
        error: ['Email or password is incorrect'],
        accessToken: null,
        refreshToken: null,
      };
    }

    const accessToken = this.generateAccessToken({
      userId: userResponse.data.id,
    });

    const refreshToken = this.generateRefreshToken({
      userId: userResponse.data.id,
    });

    await this.storeRefreshToken(userResponse.data.id, refreshToken);

    return {
      status: HttpStatus.OK,
      error: null,
      accessToken,
      refreshToken,
    };
  }

  async validate({ token }: ValidateRequestDto): Promise<ValidateResponse> {
    try {
      const secret = this.configService.get<string>('JWT_ACCESS_SECRET_KEY');

      const decoded: TokenPayload = await this.jwtService.verifyAsync(token, {
        secret,
      });

      const user = await firstValueFrom(
        this.userService.findOne({ id: decoded.userId }),
      );
      if (!user) {
        return {
          status: HttpStatus.UNAUTHORIZED,
          error: ['User not found'],
          userId: null,
          role: null,
        };
      }

      return {
        status: HttpStatus.OK,
        error: null,
        userId: decoded.userId,
        role: user.data.role,
      };
    } catch (error) {
      const status =
        error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError'
          ? HttpStatus.FORBIDDEN
          : HttpStatus.INTERNAL_SERVER_ERROR;

      return {
        status,
        error: [error.message],
        userId: null,
        role: null,
      };
    }
  }

  async storeRefreshToken(userId: string, refreshToken: string): Promise<void> {
    const hashedToken = await bcrypt.hash(refreshToken, this.SALT_ROUND);
    const expirationInMilisecond =
      this.convertToSeconds(
        this.configService.get<string>('JWT_REFRESH_EXPIRATION'),
      ) * 1000;

    await this.cacheService.set(
      userId,
      hashedToken,
      expirationInMilisecond, // Pass TTL as an option object
    );

    // Verify the token was stored
    const stored = await this.cacheService.get(userId);
  }

  generateAccessToken(payload: TokenPayload): string {
    return this.jwtService.sign(payload, {
      algorithm: 'HS256',
      secret: this.configService.get<string>('JWT_ACCESS_SECRET_KEY'),
      expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRATION'),
    });
  }

  generateRefreshToken(payload: TokenPayload): string {
    return this.jwtService.sign(payload, {
      algorithm: 'HS256',
      secret: this.configService.get<string>('JWT_REFRESH_SECRET_KEY'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION'),
    });
  }

  async refreshToken(
    payload: RefreshTokenRequest,
  ): Promise<RefreshTokenResponse> {
    try {
      const { userId, refreshToken } = payload;
      const userResponse = await firstValueFrom(
        this.userService.findOne({ id: userId }),
      );

      if (userResponse.status !== HttpStatus.OK) {
        return {
          status: HttpStatus.UNAUTHORIZED,
          error: ['User not found'],
          accessToken: null,
          refreshToken: null,
        };
      }

      const storedRefreshToken = await this.cacheService.get<string>(userId);

      if (!storedRefreshToken) {
        return {
          status: HttpStatus.UNAUTHORIZED,
          error: ['Token not found'],
          accessToken: null,
          refreshToken: null,
        };
      }
      const isValidRefreshToken = await bcrypt.compare(
        refreshToken,
        storedRefreshToken,
      );

      if (!isValidRefreshToken) {
        await this.cacheService.del(userId);
        return {
          status: HttpStatus.UNAUTHORIZED,
          error: ['Token has been revoked'],
          accessToken: null,
          refreshToken: null,
        };
      }

      const newAccessToken = this.generateAccessToken({
        userId: userResponse.data.id,
      });
      const newRefreshToken = this.generateRefreshToken({
        userId: userResponse.data.id,
      });

      await this.storeRefreshToken(userResponse.data.id, newRefreshToken);

      return {
        status: HttpStatus.OK,
        error: null,
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      };
    } catch (error) {
      return {
        status: HttpStatus.INTERNAL_SERVER_ERROR,
        error: [error.message],
        accessToken: null,
        refreshToken: null,
      };
    }
  }
}
