"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const jwt_1 = require("@nestjs/jwt");
const bcrypt = require("bcryptjs");
const rxjs_1 = require("rxjs");
const token_service_1 = require("../token/token.service");
const user_pb_1 = require("./proto-buffers/user.pb");
const cache_manager_1 = require("@nestjs/cache-manager");
let AuthService = class AuthService {
    constructor(userServiceClient, jwtService, configService, tokenService, cacheService) {
        this.userServiceClient = userServiceClient;
        this.jwtService = jwtService;
        this.configService = configService;
        this.tokenService = tokenService;
        this.cacheService = cacheService;
        this.SALT_ROUND = 10;
        this.convertToSeconds = (time) => {
            const timeValue = parseInt(time.slice(0, -1), 10);
            const timeUnit = time.slice(-1);
            switch (timeUnit) {
                case 's':
                    return timeValue;
                case 'm':
                    return timeValue * 60;
                case 'h':
                    return timeValue * 60 * 60;
                case 'd':
                    return timeValue * 24 * 60 * 60;
                default:
                    throw new Error("Invalid time format. Use 's', 'm', 'h' or 'd' (e.g., '30m' or '1h').");
            }
        };
    }
    onModuleInit() {
        this.userService =
            this.userServiceClient.getService(user_pb_1.USER_SERVICE_NAME);
    }
    async register(dto) {
        const { email, password, firstName, lastName, gender } = dto;
        const existingUserWithEmail = await (0, rxjs_1.firstValueFrom)(this.userService.findOne({ email }));
        if (existingUserWithEmail.status == common_1.HttpStatus.OK) {
            return {
                status: common_1.HttpStatus.CONFLICT,
                error: ['Email already exists'],
            };
        }
        const hashedPassword = await bcrypt.hash(password, this.SALT_ROUND);
        const createUserData = {
            email: email,
            password: hashedPassword,
            firstName: firstName,
            lastName: lastName,
            gender: gender,
        };
        const response = await (0, rxjs_1.firstValueFrom)(this.userService.createUser(createUserData));
        return {
            status: response.status,
            error: response.error,
        };
    }
    async login(dto) {
        const { email, password } = dto;
        const userResponse = await (0, rxjs_1.firstValueFrom)(this.userService.findOne({ email }));
        if (userResponse.status !== common_1.HttpStatus.OK) {
            return {
                status: common_1.HttpStatus.UNAUTHORIZED,
                error: ['User not found'],
                accessToken: null,
                refreshToken: null,
            };
        }
        const isValidPassword = await bcrypt.compare(password, userResponse.data.password);
        if (!isValidPassword) {
            return {
                status: common_1.HttpStatus.BAD_REQUEST,
                error: ['Email or password is incorrect'],
                accessToken: null,
                refreshToken: null,
            };
        }
        const accessToken = this.generateAccessToken({
            userId: userResponse.data.id,
        });
        const refreshToken = this.generateRefreshToken({
            userId: userResponse.data.id,
        });
        await this.storeRefreshToken(userResponse.data.id, refreshToken);
        return {
            status: common_1.HttpStatus.OK,
            error: null,
            accessToken,
            refreshToken,
        };
    }
    async validate({ token }) {
        try {
            const secret = this.configService.get('JWT_ACCESS_SECRET_KEY');
            const decoded = await this.jwtService.verifyAsync(token, {
                secret,
            });
            const user = await (0, rxjs_1.firstValueFrom)(this.userService.findOne({ id: decoded.userId }));
            if (!user) {
                return {
                    status: common_1.HttpStatus.CONFLICT,
                    error: ['User not found'],
                    userId: null,
                };
            }
            return { status: common_1.HttpStatus.OK, error: null, userId: decoded.userId };
        }
        catch (error) {
            const status = error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError'
                ? common_1.HttpStatus.FORBIDDEN
                : common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return {
                status,
                error: [error.message],
                userId: null,
            };
        }
    }
    async storeRefreshToken(userId, refreshToken) {
        const hashedToken = await bcrypt.hash(refreshToken, this.SALT_ROUND);
        const expirationInMilisecond = this.convertToSeconds(this.configService.get('JWT_REFRESH_EXPIRATION')) * 1000;
        await this.cacheService.set(userId, hashedToken, expirationInMilisecond);
        const stored = await this.cacheService.get(userId);
    }
    generateAccessToken(payload) {
        return this.jwtService.sign(payload, {
            algorithm: 'HS256',
            secret: this.configService.get('JWT_ACCESS_SECRET_KEY'),
            expiresIn: this.configService.get('JWT_ACCESS_EXPIRATION'),
        });
    }
    generateRefreshToken(payload) {
        return this.jwtService.sign(payload, {
            algorithm: 'HS256',
            secret: this.configService.get('JWT_REFRESH_SECRET_KEY'),
            expiresIn: this.configService.get('JWT_REFRESH_EXPIRATION'),
        });
    }
    async refreshToken(payload) {
        try {
            const { userId, refreshToken } = payload;
            const userResponse = await (0, rxjs_1.firstValueFrom)(this.userService.findOne({ id: userId }));
            if (userResponse.status !== common_1.HttpStatus.OK) {
                return {
                    status: common_1.HttpStatus.UNAUTHORIZED,
                    error: ['User not found'],
                    accessToken: null,
                    refreshToken: null,
                };
            }
            const storedRefreshToken = await this.cacheService.get(userId);
            if (!storedRefreshToken) {
                return {
                    status: common_1.HttpStatus.UNAUTHORIZED,
                    error: ['Token not found'],
                    accessToken: null,
                    refreshToken: null,
                };
            }
            const isValidRefreshToken = await bcrypt.compare(refreshToken, storedRefreshToken);
            if (!isValidRefreshToken) {
                await this.cacheService.del(userId);
                return {
                    status: common_1.HttpStatus.UNAUTHORIZED,
                    error: ['Token has been revoked'],
                    accessToken: null,
                    refreshToken: null,
                };
            }
            const newAccessToken = this.generateAccessToken({
                userId: userResponse.data.id,
            });
            const newRefreshToken = this.generateRefreshToken({
                userId: userResponse.data.id,
            });
            await this.storeRefreshToken(userResponse.data.id, newRefreshToken);
            return {
                status: common_1.HttpStatus.OK,
                error: null,
                accessToken: newAccessToken,
                refreshToken: newRefreshToken,
            };
        }
        catch (error) {
            return {
                status: common_1.HttpStatus.INTERNAL_SERVER_ERROR,
                error: [error.message],
                accessToken: null,
                refreshToken: null,
            };
        }
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(user_pb_1.USER_SERVICE_NAME)),
    __param(4, (0, common_1.Inject)(cache_manager_1.CACHE_MANAGER)),
    __metadata("design:paramtypes", [Object, jwt_1.JwtService,
        config_1.ConfigService,
        token_service_1.TokenService, Object])
], AuthService);
//# sourceMappingURL=auth.service.js.map