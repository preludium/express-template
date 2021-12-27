import { NextFunction, Router } from 'express';
import StatusCodes from 'http-status-codes';

import { UserResponse } from '@entities/user';

import { updateUserSchema } from '@entities/user/validation';
import UserService from '@service/user';
import { paramMissingError, wrongId } from '@utils/constants';
import HttpException from '@utils/exceptions/http.exception';
import { isMongoId } from '@utils/functions';
import Logger from '@utils/logger';
import { validateRequestMiddleware } from '@utils/middlewares';
import { Controller, ApiResponse } from '@utils/types/controller';

import {
    DeleteUserRequest, GetUserRequest, UpdateUserRequest
} from './types';

class UserController implements Controller {
    public readonly path = '/users';
    public readonly router = Router();
    private logger = Logger.create(__filename);
    private userService = new UserService();

    constructor() {
        this.initialiseRoutes();
    }

    private initialiseRoutes() {
        this.router.get(
            this.path,
            this.getAllUsers.bind(this)
        );

        this.router.get(
            `${this.path}/:userId`,
            this.getUser.bind(this)
        );

        this.router.put(
            `${this.path}/:userId`,
            validateRequestMiddleware(updateUserSchema),
            this.updateUser.bind(this)
        );

        this.router.delete(
            `${this.path}/:userId`,
            this.deleteUser.bind(this)
        );
    }

    private getAllUsers(_, res: ApiResponse<UserResponse[]>, next: NextFunction) {
        this.logger.info(`==> Fetching all users requested by ${res.locals.user.email}`);
        this.userService.getAllUsers()
            .then(users => {
                this.logger.info(`<== Success: fetching ${users.length} users`);
                res.status(StatusCodes.OK).send(users);
            })
            .catch(error => {
                next(new HttpException(StatusCodes.BAD_REQUEST, error.message));
            });
    }

    private getUser(req: GetUserRequest, res: ApiResponse<UserResponse>, next: NextFunction) {
        const { userId } = req.params;
        this.logger.info(`==> Fetching user of id ${userId} requested by ${res.locals.user.email}`);
        if (!isMongoId(userId)) {
            return next(new HttpException(StatusCodes.BAD_REQUEST, wrongId));
        }

        return this.userService.getUserById(userId)
            .then(user => {
                this.logger.info(`<== Success: user ${user.email} info sent back`);
                res.json(user);
            })
            .catch(error => {
                next(new HttpException(StatusCodes.NOT_FOUND, error.message));
            });
    }

    private updateUser(req: UpdateUserRequest, res: ApiResponse<UserResponse>, next: NextFunction) {
        const user = req.body;
        const { userId } = req.params;
        this.logger.info(`==> updating user with id: ${userId}`);

        if (!isMongoId(userId)) {
            return next(new HttpException(StatusCodes.BAD_REQUEST, wrongId));
        }

        if (!user) {
            return next(new HttpException(StatusCodes.BAD_REQUEST, paramMissingError));
        }

        return this.userService.updateById(userId, user)
            .then(updatedUser => {
                this.logger.info(`<== Success: user ${updatedUser?._id} updated`);
                res.json(updatedUser);
            })
            .catch(error => {
                next(new HttpException(StatusCodes.BAD_REQUEST, error.message));
            });
    }

    private async deleteUser(req: DeleteUserRequest, res: ApiResponse, next: NextFunction) {
        const { userId } = req.params;
        this.logger.info(`==> Trying to delete user ${userId} requested by ${res.locals.user.email}`);
        if (!isMongoId(userId)) {
            return next(new HttpException(StatusCodes.BAD_REQUEST, wrongId));
        }

        const { deletedCount } = await this.userService.deleteById(userId);
        if (deletedCount === 0) {
            this.logger.error('<== Failure: no user was deleted');
            return next(new HttpException(StatusCodes.NOT_FOUND, wrongId));
        }

        this.logger.info(`<== Success: user ${userId} deleted`);
        return res.status(StatusCodes.OK).send();
    }
}

export default UserController;
