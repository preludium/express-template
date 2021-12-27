import { UserRequest } from '@entities/user';
import { Request, Params } from '@utils/types/controller';

interface UserRequestParams extends Params {
    userId: string
}

// Get
export type GetUserRequest = Request<never, never, UserRequestParams>;

// Delete
export type DeleteUserRequest = Request<never, never, UserRequestParams>;

// Update
export type UpdateUserRequest = Request<UserRequest, never, UserRequestParams>;
