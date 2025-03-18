import { ArgumentsHost, RpcExceptionFilter } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
export declare class GrpcExceptionFilter implements RpcExceptionFilter<RpcException> {
    catch(exception: RpcException, host: ArgumentsHost): any;
}
export declare class AuthController {
    private readonly authService;
    private register;
    private login;
    private validate;
    private refreshToken;
}
