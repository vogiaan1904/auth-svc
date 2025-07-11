import {
  ArgumentsHost,
  Catch,
  Controller,
  Inject,
  RpcExceptionFilter,
  UseFilters,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { GrpcMethod, RpcException } from '@nestjs/microservices';
import {
  AUTH_SERVICE_NAME,
  LoginResponse,
  RefreshTokenResponse,
  ValidateResponse,
} from 'src/protos/auth.pb';
import {
  LoginRequestDto,
  RefreshTokenRequestDto,
  RegisterRequestDto,
  ValidateRequestDto,
} from './dtos/auth-request.dto';
import { throwError } from 'rxjs';

@Catch(RpcException)
export class GrpcExceptionFilter implements RpcExceptionFilter<RpcException> {
  catch(exception: RpcException, host: ArgumentsHost): any {
    return throwError(() => exception.getError());
  }
}

@UseFilters(new GrpcExceptionFilter())
@Controller('auth')
export class AuthController {
  @Inject(AuthService)
  private readonly authService: AuthService;

  @GrpcMethod(AUTH_SERVICE_NAME, 'Register')
  private async register(payload: RegisterRequestDto): Promise<void> {
    return this.authService.register(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Login')
  private async login(payload: LoginRequestDto): Promise<LoginResponse> {
    return this.authService.login(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Validate')
  private async validate(token: ValidateRequestDto): Promise<ValidateResponse> {
    return this.authService.validate(token);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'RefreshToken')
  private async refreshToken(
    payload: RefreshTokenRequestDto,
  ): Promise<RefreshTokenResponse> {
    return this.authService.refreshToken(payload);
  }
}
