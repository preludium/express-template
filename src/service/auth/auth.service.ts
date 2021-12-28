import { DocumentDefinition } from 'mongoose';

import { LoginUserRequestBody } from '@controller/auth/types';
import UserModel, { User, UserRequest, UserResponse } from '@entities/user';
import { Roles } from '@utils/constants';
import Logger from '@utils/logger';
import { verifyToken } from '@utils/middlewares';
import { TokenBundle } from '@utils/types/token';

import TokenService from '../token/token.service';

class AuthService {
    private users = UserModel;
    private tokenService = new TokenService();
    private logger = Logger.create(__filename);

    public async processLogin({
        email, password
    }: LoginUserRequestBody): Promise<TokenBundle> {
        const retrievedUser = await this.users.findOne({ email })
            .then(user => {
                if (user === null) {
                    throw new Error(`User with email ${email} does not exist`);
                }
                return user;
            })
            .catch((error) => {
                throw new Error(error.message);
            });

        const isCorrectPassword = await retrievedUser.comparePassword(password);
        if (!isCorrectPassword) {
            throw new Error('Password is not correct');
        }

        return await this.tokenService.generateTokens(retrievedUser);
    }

    public handleAuthenticate(token: string): Promise<User> {
        return verifyToken(token, 'ACCESS_TOKEN')
            .then(async (userId) => this.users.findOne({ _id: userId })
                .then(requester => {
                    if (!requester) {
                        throw new Error(`Token faulty, user of id: ${userId} does not exist`);
                    }
                    return requester;
                })
                .catch((error) => {
                    throw new Error(error.message);
                }))
            .catch(error => {
                throw new Error(error.message);
            });
    }

    public processRegister(user: DocumentDefinition<UserRequest>): Promise<UserResponse> {
        return UserModel.create({ ...user, roles: [Roles.USER] })
            .catch(error => {
                if (error.code === 11000) {
                    throw new Error(`User with email ${user.email} already exist`);
                }
                throw new Error(error.message);
            });
    }
}

export default AuthService;
