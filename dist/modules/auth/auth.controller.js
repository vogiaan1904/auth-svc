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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthController = exports.GrpcExceptionFilter = void 0;
const common_1 = require("@nestjs/common");
const auth_service_1 = require("./auth.service");
const microservices_1 = require("@nestjs/microservices");
const auth_pb_1 = require("./proto-buffers/auth.pb");
const auth_request_dto_1 = require("./dto/auth-request.dto");
const rxjs_1 = require("rxjs");
let GrpcExceptionFilter = class GrpcExceptionFilter {
    catch(exception, host) {
        return (0, rxjs_1.throwError)(() => exception.getError());
    }
};
exports.GrpcExceptionFilter = GrpcExceptionFilter;
exports.GrpcExceptionFilter = GrpcExceptionFilter = __decorate([
    (0, common_1.Catch)(microservices_1.RpcException)
], GrpcExceptionFilter);
let AuthController = class AuthController {
    async register(payload) {
        return this.authService.register(payload);
    }
    async login(payload) {
        return this.authService.login(payload);
    }
    async validate(token) {
        return this.authService.validate(token);
    }
    async refreshToken(payload) {
        return this.authService.refreshToken(payload);
    }
};
exports.AuthController = AuthController;
__decorate([
    (0, common_1.Inject)(auth_service_1.AuthService),
    __metadata("design:type", auth_service_1.AuthService)
], AuthController.prototype, "authService", void 0);
__decorate([
    (0, microservices_1.GrpcMethod)(auth_pb_1.AUTH_SERVICE_NAME, 'Register'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_request_dto_1.RegisterRequestDto]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "register", null);
__decorate([
    (0, microservices_1.GrpcMethod)(auth_pb_1.AUTH_SERVICE_NAME, 'Login'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_request_dto_1.LoginRequestDto]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "login", null);
__decorate([
    (0, microservices_1.GrpcMethod)(auth_pb_1.AUTH_SERVICE_NAME, 'Validate'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_request_dto_1.ValidateRequestDto]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "validate", null);
__decorate([
    (0, microservices_1.GrpcMethod)(auth_pb_1.AUTH_SERVICE_NAME, 'RefreshToken'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_request_dto_1.RefreshTokenRequestDto]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "refreshToken", null);
exports.AuthController = AuthController = __decorate([
    (0, common_1.UseFilters)(new GrpcExceptionFilter()),
    (0, common_1.Controller)('auth')
], AuthController);
//# sourceMappingURL=auth.controller.js.map