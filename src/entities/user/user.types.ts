import { Document } from 'mongoose';

import { Roles } from '@utils/constants';

export interface User extends Document {
    email: string;
    password: string;
    roles: Roles[];
    createdAt: Date;
    comparePassword(candidatePassword: string): Promise<boolean>;
}

export type UserResponse = Omit<User, 'password' | 'comparePassword' | '_id'> & { id?: string };

export type UserRequest = Pick<User, 'email' | 'password'>;
