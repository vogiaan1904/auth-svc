import { Transform } from 'class-transformer';
import { IsEmail, IsEnum, IsNotEmpty, IsString } from 'class-validator';
import {
  LoginRequest,
  RefreshTokenRequest,
  RegisterRequest,
  ValidateRequest,
} from 'src/protos/auth.pb';

export enum Gender {
  MALE = 'MALE',
  FEMALE = 'FEMALE',
  OTHER = 'OTHER',
}

export enum Role {
  ADMIN = 'ADMIN',
  USER = 'USER',
}

export class LoginRequestDto implements LoginRequest {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}

export class RegisterRequestDto implements RegisterRequest {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsNotEmpty()
  @IsString()
  firstName: string;

  @IsString()
  @IsNotEmpty()
  lastName: string;

  @IsNotEmpty()
  @IsEnum(Gender)
  @Transform(({ value }) => value.toUpperCase())
  gender: string;
}

export class ValidateRequestDto implements ValidateRequest {
  @IsNotEmpty()
  @IsString()
  token: string;
}

export class RefreshTokenRequestDto implements RefreshTokenRequest {
  @IsNotEmpty()
  @IsString()
  refreshToken: string;

  @IsNotEmpty()
  @IsString()
  userId;
}
