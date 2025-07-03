import { INestMicroservice, Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { Transport } from '@nestjs/microservices';
import { join } from 'path';
import { AppModule } from './app.module';
import { RpcInvalidArgumentException } from './common/exceptions/rpc.exception';
import { GlobalExceptionFilter } from './common/filters/grpc-exception.filter';
import { AUTH_PACKAGE_NAME } from './protos/auth.pb';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const PORT = process.env.PORT || 50051;
  const app: INestMicroservice = await NestFactory.createMicroservice(
    AppModule,
    {
      transport: Transport.GRPC,
      options: {
        url: `0.0.0.0:${PORT}`,
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
        logger.error('Validation failed', errors);
        throw new RpcInvalidArgumentException('Validation failed');
      },
    }),
  );

  app.useGlobalFilters(new GlobalExceptionFilter());
  await app.listen();
}
bootstrap();
