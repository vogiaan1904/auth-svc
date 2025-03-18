import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Transport } from '@nestjs/microservices';
import { INestMicroservice, ValidationPipe } from '@nestjs/common';
import { protobufPackage } from './modules/auth/proto-buffers/auth.pb';
import { join } from 'path';
import { HttpExceptionFilter } from './modules/auth/filter/http-exception.filter';
import { GrpcLoggingInterceptor } from './interceptor/grpc-logging.interceptor';

async function bootstrap() {
  const app: INestMicroservice = await NestFactory.createMicroservice(
    AppModule,
    {
      transport: Transport.GRPC,
      options: {
        url: '0.0.0.0:50051',
        package: protobufPackage,
        protoPath: join('node_modules/grpc-nest-proto/proto/auth.proto'),
      },
    },
  );
  app.useGlobalFilters(new HttpExceptionFilter());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
  await app.listen();
}
bootstrap();
