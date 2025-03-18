import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as Joi from 'joi';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './modules/auth/auth.module';
import { TokenModule } from './modules/token/token.module';
import loggerConfig from './configs/logger.config';
import { CacheModule } from '@nestjs/cache-manager';
import * as redisStore from 'cache-manager-redis-yet';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [loggerConfig],
      validationSchema: Joi.object({
        NODE_ENV: Joi.string()
          .valid('development', 'production', 'test', 'provision', 'staging')
          .default('development'),
        JWT_ACCESS_SECRET_KEY: Joi.string().required(),
        JWT_REFRESH_SECRET_KEY: Joi.string().required(),
        //...
      }),
      validationOptions: {
        abortEarly: false,
      },
      isGlobal: true,
      envFilePath:
        process.env.NODE_ENV === 'development' ? '.env' : '.env.prod',
      cache: true,
      expandVariables: true,
    }),
    CacheModule.registerAsync({
      isGlobal: true,
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        const cacheUrl = configService.get<string>('REDIS_URL');
        console.log('Cache URL:', cacheUrl);
        return {
          store: redisStore.redisStore,
          url: cacheUrl,
          ttl: 3600,
        };
      },
      inject: [ConfigService],
    }),
    AuthModule,
    TokenModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
