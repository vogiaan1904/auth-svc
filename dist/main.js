"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = require("@nestjs/core");
const app_module_1 = require("./app.module");
const microservices_1 = require("@nestjs/microservices");
const common_1 = require("@nestjs/common");
const auth_pb_1 = require("./modules/auth/proto-buffers/auth.pb");
const path_1 = require("path");
const http_exception_filter_1 = require("./modules/auth/filter/http-exception.filter");
async function bootstrap() {
    const app = await core_1.NestFactory.createMicroservice(app_module_1.AppModule, {
        transport: microservices_1.Transport.GRPC,
        options: {
            url: '0.0.0.0:50051',
            package: auth_pb_1.protobufPackage,
            protoPath: (0, path_1.join)('node_modules/grpc-nest-proto/proto/auth.proto'),
        },
    });
    app.useGlobalFilters(new http_exception_filter_1.HttpExceptionFilter());
    app.useGlobalPipes(new common_1.ValidationPipe({ whitelist: true, transform: true }));
    await app.listen();
}
bootstrap();
//# sourceMappingURL=main.js.map