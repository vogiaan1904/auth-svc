import { ArgumentsHost, ExceptionFilter, HttpException, HttpStatus } from '@nestjs/common';
export declare class HttpExceptionFilter implements ExceptionFilter {
    catch(exception: HttpException, host: ArgumentsHost): {
        status: HttpStatus;
        error: any;
    };
}
