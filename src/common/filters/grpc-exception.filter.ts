// src/common/filters/grpc-exception.filter.ts
import { status as GrpcStatus } from '@grpc/grpc-js';
import {
  ArgumentsHost,
  BadRequestException,
  Catch,
  Logger,
  RpcExceptionFilter,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';

@Catch()
export class AllExceptionsFilter implements RpcExceptionFilter<any> {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: any, host: ArgumentsHost): Observable<any> {
    this.logger.debug(
      'Full exception object:',
      JSON.stringify(exception, null, 2),
    );

    if (
      exception instanceof BadRequestException ||
      exception.code === GrpcStatus.INVALID_ARGUMENT
    ) {
      const errorDetails = exception.response?.message || exception.message;
      return throwError(() => ({
        code: GrpcStatus.INVALID_ARGUMENT,
        message: 'Validation failed',
        details: Array.isArray(errorDetails)
          ? errorDetails.join(', ')
          : errorDetails,
      }));
    }

    if (exception.code !== undefined) {
      return throwError(() => ({
        code: exception.code,
        message: exception.message,
        details: exception.details,
      }));
    }

    this.logger.error(
      `Unhandled exception: ${exception.message}`,
      exception.stack,
    );

    return throwError(() => ({
      code: GrpcStatus.INTERNAL,
      message: 'Internal server error',
      details: null,
    }));
  }
}
