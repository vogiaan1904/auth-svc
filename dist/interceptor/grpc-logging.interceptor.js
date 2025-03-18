"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GrpcLoggingInterceptor = void 0;
const common_1 = require("@nestjs/common");
const GrpcLoggingInterceptor = (path, redactedFields) => {
    const logger = new common_1.Logger('GrpcLoggingInterceptor');
    function redact(data) {
        return JSON.stringify(data, (key, value) => (redactedFields.includes(key) ? '[Redacted]' : value), 2);
    }
    return {
        start: function (metadata, listener, next) {
            const newListener = {
                onReceiveMetadata: function (metadata, next) {
                    logger.verbose(`response metadata : ${redact(metadata)}`);
                    next(metadata);
                },
                onReceiveMessage: function (message, next) {
                    logger.verbose(`response body : ${redact(message)}`);
                    next(message);
                },
                onReceiveStatus: function (status, next) {
                    logger.verbose(`response status : ${redact(status)}`);
                    next(status);
                },
            };
            next(metadata, newListener);
        },
        sendMessage: function (message, next) {
            logger.verbose(`path: ${JSON.stringify(path)}`);
            logger.verbose(`request body : ${redact(message)}`);
            next(message);
        },
    };
};
exports.GrpcLoggingInterceptor = GrpcLoggingInterceptor;
//# sourceMappingURL=grpc-logging.interceptor.js.map