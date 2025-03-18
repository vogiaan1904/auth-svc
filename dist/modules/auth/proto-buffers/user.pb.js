"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.USER_SERVICE_NAME = exports.USER_PACKAGE_NAME = exports.protobufPackage = void 0;
exports.UserServiceControllerMethods = UserServiceControllerMethods;
const microservices_1 = require("@nestjs/microservices");
exports.protobufPackage = "user";
exports.USER_PACKAGE_NAME = "user";
function UserServiceControllerMethods() {
    return function (constructor) {
        const grpcMethods = ["createUser", "findOne", "findAll", "updateUser", "deleteUser"];
        for (const method of grpcMethods) {
            const descriptor = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
            (0, microservices_1.GrpcMethod)("UserService", method)(constructor.prototype[method], method, descriptor);
        }
        const grpcStreamMethods = [];
        for (const method of grpcStreamMethods) {
            const descriptor = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
            (0, microservices_1.GrpcStreamMethod)("UserService", method)(constructor.prototype[method], method, descriptor);
        }
    };
}
exports.USER_SERVICE_NAME = "UserService";
//# sourceMappingURL=user.pb.js.map