import { Logger, Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { JwtModule } from '@nestjs/jwt';
import { TokenModule } from 'src/modules/token/token.module';
import { ConfigService } from '@nestjs/config';
import { InterceptingCall } from '@grpc/grpc-js';
import { GrpcLoggingInterceptor } from 'src/interceptor/grpc-logging.interceptor';
import { USER_PACKAGE_NAME } from 'src/protos/user.pb';
import { USER_SERVICE_NAME } from 'src/protos/user.pb';

@Module({
  imports: [
    JwtModule.register({}),
    TokenModule,
    ClientsModule.registerAsync([
      {
        name: USER_SERVICE_NAME,
        useFactory: async (configService: ConfigService) => ({
          transport: Transport.GRPC,
          options: {
            url: configService.get<string>('USER_SERVICE_ADDRESS'),
            package: USER_PACKAGE_NAME,
            protoPath: 'node_modules/grpc-nest-proto/proto/user.proto',
            channelOptions: {
              interceptors: [
                (options, nextCall) => {
                  const logger: Logger = new Logger(AuthModule.name);

                  const redactedFields: string[] = configService.get<string[]>(
                    'logger.redact.fields',
                  );
                  const path: string = options.method_definition.path;

                  logger.verbose('----------- GRPC CALL ------------');

                  const interceptingCall = new InterceptingCall(
                    nextCall(options),
                    GrpcLoggingInterceptor(path, redactedFields),
                  );

                  return interceptingCall;
                },
              ],
            },
          },
        }),
        inject: [ConfigService],
      },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
