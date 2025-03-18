import { ConfigService } from '@nestjs/config';
import { Strategy } from 'passport-jwt';
import { TokenPayload } from 'src/modules/auth/interfaces/token.interface';
declare const JwtAccessTokenStrategy_base: new (...args: [opt: import("passport-jwt").StrategyOptionsWithRequest] | [opt: import("passport-jwt").StrategyOptionsWithoutRequest]) => Strategy & {
    validate(...args: any[]): unknown;
};
export declare class JwtAccessTokenStrategy extends JwtAccessTokenStrategy_base {
    private readonly configService;
    private readonly jwtService;
    constructor(configService: ConfigService);
    validate({ userId }: TokenPayload): void;
}
export {};
