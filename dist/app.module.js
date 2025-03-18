"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppModule = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const Joi = require("joi");
const app_controller_1 = require("./app.controller");
const app_service_1 = require("./app.service");
const auth_module_1 = require("./modules/auth/auth.module");
const token_module_1 = require("./modules/token/token.module");
const logger_config_1 = require("./configs/logger.config");
const cache_manager_1 = require("@nestjs/cache-manager");
const redisStore = require("cache-manager-redis-yet");
let AppModule = class AppModule {
};
exports.AppModule = AppModule;
exports.AppModule = AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                load: [logger_config_1.default],
                validationSchema: Joi.object({
                    NODE_ENV: Joi.string()
                        .valid('development', 'production', 'test', 'provision', 'staging')
                        .default('development'),
                    JWT_ACCESS_SECRET_KEY: Joi.string().required(),
                    JWT_REFRESH_SECRET_KEY: Joi.string().required(),
                }),
                validationOptions: {
                    abortEarly: false,
                },
                isGlobal: true,
                envFilePath: process.env.NODE_ENV === 'development' ? '.env' : '.env.prod',
                cache: true,
                expandVariables: true,
            }),
            cache_manager_1.CacheModule.registerAsync({
                isGlobal: true,
                imports: [config_1.ConfigModule],
                useFactory: async (configService) => {
                    const cacheUrl = configService.get('REDIS_URL');
                    console.log('Cache URL:', cacheUrl);
                    return {
                        store: redisStore.redisStore,
                        url: cacheUrl,
                        ttl: 3600,
                    };
                },
                inject: [config_1.ConfigService],
            }),
            auth_module_1.AuthModule,
            token_module_1.TokenModule,
        ],
        controllers: [app_controller_1.AppController],
        providers: [app_service_1.AppService],
    })
], AppModule);
//# sourceMappingURL=app.module.js.map