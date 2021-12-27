import { User, UserRequest } from '@entities/user';
import { Request } from '@utils/types/controller';

// Login
export type LoginUserRequestBody = Pick<User, 'email' | 'password'>;

export type LoginUserRequest = Request<LoginUserRequestBody, never, never>;

// Register
type UserRequestBody = UserRequest;

export type RegisterUserRequest = Request<UserRequestBody, never, never>;
