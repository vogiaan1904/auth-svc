import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ClientGrpc } from '@nestjs/microservices';
import * as bcrypt from 'bcryptjs';
import { Cache } from 'cache-manager';
import { firstValueFrom } from 'rxjs';
import {
  RpcInvalidArgumentException,
  RpcUnauthenticatedException,
} from 'src/common/exceptions/rpc.exception';
import { TokenService } from 'src/modules/token/token.service';
import {
  ForgotPasswordRequest,
  LoginRequest,
  LoginResponse,
  RefreshTokenRequest,
  RefreshTokenResponse,
  ResetPasswordRequest,
  SendVerificationEmailRequest,
  ValidateResponse,
} from 'src/protos/auth.pb';
import {
  CreateUserRequest,
  FindOneResponse,
  USER_SERVICE_NAME,
  UserServiceClient,
} from 'src/protos/user.pb';
import { convertToSeconds } from 'src/utils/time.util';
import {
  RegisterRequestDto,
  Role,
  ValidateRequestDto,
} from './dtos/auth-request.dto';
import { TokenPayload } from './interfaces/token.interface';
import { AuthErrors } from 'src/common/constants/errors.constant';
@Injectable()
export class AuthService implements OnModuleInit {
  private readonly SALT_ROUND: number = 10;
  private userService: UserServiceClient;

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

  private generateAccessToken(payload: TokenPayload): string {
    return this.jwtService.sign(payload, {
      algorithm: 'HS256',
      secret: this.configService.get<string>('JWT_ACCESS_SECRET_KEY'),
      expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRATION'),
    });
  }

  private generateRefreshToken(payload: TokenPayload): string {
    return this.jwtService.sign(payload, {
      algorithm: 'HS256',
      secret: this.configService.get<string>('JWT_REFRESH_SECRET_KEY'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION'),
    });
  }

  private async storeRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<void> {
    const hashedToken = await bcrypt.hash(refreshToken, this.SALT_ROUND);
    const expirationInMilisecond =
      convertToSeconds(
        this.configService.get<string>('JWT_REFRESH_EXPIRATION'),
      ) * 1000;

    await this.cacheService.set(
      userId,
      hashedToken,
      expirationInMilisecond, // Pass TTL as an option object
    );

    const stored = await this.cacheService.get(userId);
  }

  async register(dto: RegisterRequestDto): Promise<void> {
    const { email, password, firstName, lastName, gender } = dto;

    const findOneResp: FindOneResponse = await firstValueFrom(
      this.userService.findOne({ email }),
    );

    if (findOneResp.user !== null) {
      throw new RpcInvalidArgumentException('User already exists');
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
  }

  async login(dto: LoginRequest): Promise<LoginResponse> {
    const { email, password } = dto;
    const findOneResp = await firstValueFrom(
      this.userService.findOne({ email }),
    );

    if (findOneResp.user == null) {
      throw new RpcInvalidArgumentException('Invalid credentials');
    }

    const isValidPassword = await bcrypt.compare(
      password,
      findOneResp.user.password,
    );
    if (!isValidPassword) {
      throw new RpcInvalidArgumentException('Invalid credentials');
    }

    const accessToken = this.generateAccessToken({
      userId: findOneResp.user.id,
    });

    const refreshToken = this.generateRefreshToken({
      userId: findOneResp.user.id,
    });

    await this.storeRefreshToken(findOneResp.user.id, refreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }

  async validate({ token }: ValidateRequestDto): Promise<ValidateResponse> {
    const secret = this.configService.get<string>('JWT_ACCESS_SECRET_KEY');

    var decoded: TokenPayload;
    try {
      decoded = await this.jwtService.verifyAsync(token, {
        secret,
      });
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new RpcUnauthenticatedException(AuthErrors.TOKEN_EXPIRED);
      }
      throw new RpcUnauthenticatedException(AuthErrors.INVALID_TOKEN);
    }

    const findOneResp = await firstValueFrom(
      this.userService.findOne({ id: decoded.userId }),
    );
    if (findOneResp.user == null) {
      throw new RpcUnauthenticatedException('Invalid token');
    }

    

    return {
      userId: decoded.userId,
      role: findOneResp.user.role,
    };
  }

  async refreshToken(
    payload: RefreshTokenRequest,
  ): Promise<RefreshTokenResponse> {
    const { userId, refreshToken } = payload;
    const userResponse = await firstValueFrom(
      this.userService.findOne({ id: userId }),
    );

    if (userResponse.user == null) {
      throw new RpcUnauthenticatedException('Invalid token');
    }

    const storedRefreshToken = await this.cacheService.get<string>(userId);

    if (!storedRefreshToken) {
      throw new RpcUnauthenticatedException('Invalid token');
    }
    const isValidRefreshToken = await bcrypt.compare(
      refreshToken,
      storedRefreshToken,
    );

    if (!isValidRefreshToken) {
      await this.cacheService.del(userId);
      throw new RpcUnauthenticatedException('Invalid token');
    }

    const newAccessToken = this.generateAccessToken({
      userId: userResponse.user.id,
    });
    const newRefreshToken = this.generateRefreshToken({
      userId: userResponse.user.id,
    });

    await this.storeRefreshToken(userResponse.user.id, newRefreshToken);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }

  async sendVerificationEmail(
    dto: SendVerificationEmailRequest,
  ): Promise<void> {}

  async forgotPassword(dto: ForgotPasswordRequest): Promise<void> {}

  async resetPassword(dto: ResetPasswordRequest): Promise<void> {}
}
