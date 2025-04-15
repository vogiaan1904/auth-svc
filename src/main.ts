import { status as GrpcStatus } from '@grpc/grpc-js';
import {
  INestMicroservice,
  Logger,
  ValidationPipe,
  BadRequestException,
} from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { Transport } from '@nestjs/microservices';
import { join } from 'path';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters/grpc-exception.filter';
import { AUTH_PACKAGE_NAME } from './protos/auth.pb';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app: INestMicroservice = await NestFactory.createMicroservice(
    AppModule,
    {
      transport: Transport.GRPC,
      options: {
        url: '127.0.0.1:50051',
        package: AUTH_PACKAGE_NAME,
        protoPath: join('node_modules/grpc-nest-proto/proto/auth.proto'),
      },
    },
  );

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      exceptionFactory: (errors) => {
        throw new BadRequestException({
          code: GrpcStatus.INVALID_ARGUMENT,
          message: 'Validation failed',
          details: errors,
        });
      },
    }),
  );

  app.useGlobalFilters(new AllExceptionsFilter());
  await app.listen();
}
bootstrap();
