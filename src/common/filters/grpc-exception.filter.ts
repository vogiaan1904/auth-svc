// src/common/filters/grpc-exception.filter.ts
import {
  ArgumentsHost,
  Catch,
  Logger,
  RpcExceptionFilter,
  BadRequestException,
  HttpStatus,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { status as GrpcStatus } from '@grpc/grpc-js';
import { RpcException } from '@nestjs/microservices';

@Catch()
export class AllExceptionsFilter implements RpcExceptionFilter<any> {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: any, host: ArgumentsHost): Observable<any> {
    console.log('exception', exception);
    // Add more detailed logging
    this.logger.error(`Exception caught: ${exception.name}`);
    this.logger.error(`Message: ${exception.message}`);

    // Log the full exception object for debugging
    this.logger.debug(
      'Full exception object:',
      JSON.stringify(exception, null, 2),
    );

    // Handle BadRequestException (validation errors)
    if (
      exception instanceof BadRequestException ||
      exception.name === 'ValidationError' ||
      exception.name === 'BadRequestException'
    ) {
      // Extract details from the exception
      let errorDetails = [];

      // Log the response structure
      if (exception.response) {
        this.logger.debug(
          'Validation response:',
          JSON.stringify(exception.response),
        );
      }

      // Handle NestJS validation errors format
      if (exception.response && exception.response.message) {
        errorDetails = Array.isArray(exception.response.message)
          ? exception.response.message
          : [exception.response.message];
      } else if (exception.message) {
        errorDetails = Array.isArray(exception.message)
          ? exception.message
          : [exception.message];
      }

      // Log the extracted details
      this.logger.error(
        `Validation failed with errors: ${errorDetails.join(', ')}`,
      );

      return throwError(() => ({
        code: GrpcStatus.INVALID_ARGUMENT,
        message: errorDetails.join(', '),
        details: errorDetails.join(', '),
      }));
    }

    // All other errors - log and return your standard error response
    this.logger.error(
      `Unhandled exception: ${exception.message}`,
      exception.stack,
    );

    const error = {
      code: GrpcStatus.INTERNAL, // 13 for INTERNAL
      message: 'Internal server error',
      metadata: exception.message,
    };
    return throwError(() => error);
  }
}
