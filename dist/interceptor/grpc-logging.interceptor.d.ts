export declare const GrpcLoggingInterceptor: (path: string, redactedFields: string[]) => {
    start: (metadata: any, listener: any, next: any) => void;
    sendMessage: (message: any, next: any) => void;
};
