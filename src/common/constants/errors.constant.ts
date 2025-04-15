import { ErrorCode } from '../../protos/auth.pb';

export const AuthErrors = {
  OK: {
    code: ErrorCode.OK,
    message: 'Success',
  },
  INVALID_CREDENTIALS: {
    code: ErrorCode.INVALID_CREDENTIALS,
    message: 'Invalid credentials',
  },
  INVALID_TOKEN: {
    code: ErrorCode.INVALID_TOKEN,
    message: 'Invalid authentication token',
  },
  TOKEN_EXPIRED: {
    code: ErrorCode.TOKEN_EXPIRED,
    message: 'Authentication token has expired',
  },
  REFRESH_TOKEN_EXPIRED: {
    code: ErrorCode.REFRESH_TOKEN_EXPIRED,
    message: 'Refresh token has expired',
  },
  TOKEN_NOT_FOUND: {
    code: ErrorCode.TOKEN_NOT_FOUND,
    message: 'Authentication token not found',
  },
  EMAIL_ALREADY_EXISTS: {
    code: ErrorCode.EMAIL_ALREADY_EXISTS,
    message: 'Email address is already registered',
  },
  INVALID_EMAIL_FORMAT: {
    code: ErrorCode.INVALID_EMAIL_FORMAT,
    message: 'Invalid email format',
  },
  INVALID_PASSWORD_FORMAT: {
    code: ErrorCode.INVALID_PASSWORD_FORMAT,
    message: 'Password does not meet security requirements',
  },
  REGISTRATION_FAILED: {
    code: ErrorCode.REGISTRATION_FAILED,
    message: 'Failed to register user',
  },
  EMAIL_NOT_VERIFIED: {
    code: ErrorCode.EMAIL_NOT_VERIFIED,
    message: 'Email address not verified',
  },
  VERIFICATION_TOKEN_EXPIRED: {
    code: ErrorCode.VERIFICATION_TOKEN_EXPIRED,
    message: 'Email verification token has expired',
  },
  VERIFICATION_TOKEN_INVALID: {
    code: ErrorCode.VERIFICATION_TOKEN_INVALID,
    message: 'Invalid email verification token',
  },
  RESET_TOKEN_EXPIRED: {
    code: ErrorCode.RESET_TOKEN_EXPIRED,
    message: 'Password reset token has expired',
  },
  RESET_TOKEN_INVALID: {
    code: ErrorCode.RESET_TOKEN_INVALID,
    message: 'Invalid password reset token',
  },
  PASSWORD_RESET_FAILED: {
    code: ErrorCode.PASSWORD_RESET_FAILED,
    message: 'Failed to reset password',
  },
  UNRECOGNIZED: {
    code: ErrorCode.UNRECOGNIZED,
    message: 'Unknown error occurred',
  },
};
