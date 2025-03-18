export interface SignTokenWithSecretInterface {
    payload: object;
    secret: string;
    exp: string;
}
export interface VerifyTokenWithSecretInterface {
    token: string;
    secret: string;
}
