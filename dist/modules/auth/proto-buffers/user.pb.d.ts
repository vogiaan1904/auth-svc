import { Observable } from "rxjs";
export declare const protobufPackage = "user";
export interface Address {
    street: string;
    city: string;
    state: string;
    postalCode: string;
    country: string;
    isDefault: boolean;
}
export interface UserData {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    phoneNumber: string;
    gender: string;
    avatar: string;
    addresses: Address[];
    password: string;
}
export interface CreateUserRequest {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    gender: string;
}
export interface CreateUserResponse {
    status: number;
    error: string[];
    id: string;
}
export interface FindOneRequest {
    id?: string | undefined;
    email?: string | undefined;
}
export interface FindOneResponse {
    status: number;
    error: string[];
    data: UserData | undefined;
}
export interface FindAllRequest {
    page: number;
    limit: number;
}
export interface FindAllResponse {
    status: number;
    error: string[];
    data: UserData[];
    total: number;
}
export interface UpdateUserRequest {
    id: string;
    firstName: string;
    lastName: string;
    phoneNumber: string;
    avatar: string;
}
export interface UpdateUserResponse {
    status: number;
    error: string[];
}
export interface DeleteUserRequest {
    id: string;
}
export interface DeleteUserResponse {
    status: number;
    error: string[];
}
export declare const USER_PACKAGE_NAME = "user";
export interface UserServiceClient {
    createUser(request: CreateUserRequest): Observable<CreateUserResponse>;
    findOne(request: FindOneRequest): Observable<FindOneResponse>;
    findAll(request: FindAllRequest): Observable<FindAllResponse>;
    updateUser(request: UpdateUserRequest): Observable<UpdateUserResponse>;
    deleteUser(request: DeleteUserRequest): Observable<DeleteUserResponse>;
}
export interface UserServiceController {
    createUser(request: CreateUserRequest): Promise<CreateUserResponse> | Observable<CreateUserResponse> | CreateUserResponse;
    findOne(request: FindOneRequest): Promise<FindOneResponse> | Observable<FindOneResponse> | FindOneResponse;
    findAll(request: FindAllRequest): Promise<FindAllResponse> | Observable<FindAllResponse> | FindAllResponse;
    updateUser(request: UpdateUserRequest): Promise<UpdateUserResponse> | Observable<UpdateUserResponse> | UpdateUserResponse;
    deleteUser(request: DeleteUserRequest): Promise<DeleteUserResponse> | Observable<DeleteUserResponse> | DeleteUserResponse;
}
export declare function UserServiceControllerMethods(): (constructor: Function) => void;
export declare const USER_SERVICE_NAME = "UserService";
