import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ClientGrpc } from '@nestjs/microservices';
import * as bcrypt from 'bcryptjs';
import { Cache } from 'cache-manager';
import { firstValueFrom } from 'rxjs';
import { AuthErrors } from 'src/common/constants/errors.constant';
import { TokenService } from 'src/modules/token/token.service';
import {
  LoginRequest,
  LoginResponse,
  RefreshTokenRequest,
  RefreshTokenResponse,
  RegisterResponse,
  ValidateResponse,
} from 'src/protos/auth.pb';
import {
  CreateUserRequest,
  FindOneResponse,
  USER_SERVICE_NAME,
  ErrorCode as UserErrorCode,
  UserServiceClient,
} from 'src/protos/user.pb';
import {
  RegisterRequestDto,
  Role,
  ValidateRequestDto,
} from './dto/auth-request.dto';
import { TokenPayload } from './interfaces/token.interface';
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

    const findOneResp: FindOneResponse = await firstValueFrom(
      this.userService.findOne({ email }),
    );

    if (findOneResp.error.code == UserErrorCode.OK) {
      return {
        error: AuthErrors.EMAIL_ALREADY_EXISTS,
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

    await firstValueFrom(this.userService.createUser(createUserData));

    return {
      error: AuthErrors.OK,
    };
  }

  async login(dto: LoginRequest): Promise<LoginResponse> {
    const { email, password } = dto;
    const findOneResp = await firstValueFrom(
      this.userService.findOne({ email }),
    );

    console.log('findOneResp', findOneResp);

    if (findOneResp.error.code == UserErrorCode.USER_NOT_FOUND) {
      console.log('User not found');
      return {
        error: AuthErrors.INVALID_CREDENTIALS,
        accessToken: null,
        refreshToken: null,
      };
    }

    const isValidPassword = await bcrypt.compare(
      password,
      findOneResp.data.password,
    );
    if (!isValidPassword) {
      return {
        error: AuthErrors.INVALID_CREDENTIALS,
        accessToken: null,
        refreshToken: null,
      };
    }

    const accessToken = this.generateAccessToken({
      userId: findOneResp.data.id,
    });

    const refreshToken = this.generateRefreshToken({
      userId: findOneResp.data.id,
    });

    await this.storeRefreshToken(findOneResp.data.id, refreshToken);

    return {
      error: AuthErrors.OK,
      accessToken,
      refreshToken,
    };
  }

  async validate({ token }: ValidateRequestDto): Promise<ValidateResponse> {
    const secret = this.configService.get<string>('JWT_ACCESS_SECRET_KEY');

    const decoded: TokenPayload = await this.jwtService.verifyAsync(token, {
      secret,
    });

    const findOneResp = await firstValueFrom(
      this.userService.findOne({ id: decoded.userId }),
    );
    if (findOneResp.error.code == UserErrorCode.USER_NOT_FOUND) {
      return {
        error: AuthErrors.INVALID_TOKEN,
        userId: null,
        role: null,
      };
    }

    return {
      error: AuthErrors.OK,
      userId: decoded.userId,
      role: findOneResp.data.role,
    };
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
    const { userId, refreshToken } = payload;
    const userResponse = await firstValueFrom(
      this.userService.findOne({ id: userId }),
    );

    if (userResponse.error.code == UserErrorCode.USER_NOT_FOUND) {
      return {
        error: AuthErrors.INVALID_TOKEN,
        accessToken: null,
        refreshToken: null,
      };
    }

    const storedRefreshToken = await this.cacheService.get<string>(userId);

    if (!storedRefreshToken) {
      return {
        error: AuthErrors.TOKEN_NOT_FOUND,
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
        error: AuthErrors.INVALID_TOKEN,
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
      error: AuthErrors.OK,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }
}
