import dayjs from 'dayjs';
import { NextFunction, Router } from 'express';
import StatusCodes from 'http-status-codes';

import {
    loginUserSchema,
    registerUserSchema,
    responseMessage as loginErrorMessage
} from '@entities/user';
import AuthService from '@service/auth/auth.service';
import HttpException from '@utils/exceptions/http.exception';
import Logger from '@utils/logger';
import { validateRequestMiddleware } from '@utils/middlewares';
import { Controller, Response, Request, ApiResponse } from '@utils/types/controller';

import { LoginUserRequest, RegisterUserRequest } from './types';

class AuthController implements Controller {
    public readonly path = '';
    public readonly router = Router();
    private logger = Logger.create(__filename);
    private authService = new AuthService();

    constructor() {
        this.initialiseRoutes();
    }

    private initialiseRoutes() {
        this.router.use('/api', this.authenticate.bind(this));

        this.router.post(
            `${this.path}/login`,
            validateRequestMiddleware(loginUserSchema),
            this.login.bind(this)
        );

        this.router.post(
            `${this.path}/register`,
            validateRequestMiddleware(registerUserSchema),
            this.register.bind(this)
        );

        this.router.get(
            `${this.path}/logout`,
            this.logout.bind(this)
        );
    }

    private authenticate(req: Request, res: Response, next: NextFunction) {
        this.logger.info('Trying to authenticate user with access-token');

        const token = req.cookies['access-token'];
        if (!token) {
            this.logger.error('<== Failure: access-token does not exist');
            return res.status(StatusCodes.UNAUTHORIZED).end();
        }

        return this.authService.handleAuthenticate(token)
            .then(requester => {
                res.locals.user = requester;
                this.logger.info(`User ${requester.email} successfully authenticated`);
                next();
            })
            .catch((error) => {
                this.logger.error(`Failure: ${error.message}`);
                res.status(StatusCodes.FORBIDDEN).end();
            });
    }

    private login(req: LoginUserRequest, res: Response, next: NextFunction) {
        this.logger.info(`==> user ${req.body.email} is trying to log in`);
        this.authService.processLogin(req.body)
            .then(({ accessToken, refreshToken }) => {
                res
                    .cookie('access-token', accessToken, {
                        httpOnly: true,
                        expires: dayjs()
                            .add(15, 'm')
                            .toDate()
                    })
                    .cookie('refresh-token', refreshToken, {
                        httpOnly: true,
                        expires: dayjs()
                            .add(5, 'd')
                            .toDate()
                    })
                    .end();
                this.logger.info(`<== Success: user ${req.body.email} logged in`);
            })
            .catch((error) => {
                this.logger.error(error.message);
                next(new HttpException(StatusCodes.BAD_REQUEST, loginErrorMessage));
            });
    }

    private register(req: RegisterUserRequest, res: Response, next: NextFunction) {
        const user = req.body;
        this.logger.info(`==> Creating user with email: ${user.email}`);

        this.authService.processRegister(user)
            .then(newUser => {
                this.logger.info(`<== Success: user ${newUser.email} users`);
                res.status(StatusCodes.CREATED).json(newUser);
            })
            .catch(error => {
                next(new HttpException(StatusCodes.BAD_REQUEST, error.message));
            });
    }

    private async logout(req: Request, res: ApiResponse) {
        const user = await this.authenticateUserForLogout(req);

        if (user) {
            this.logger.info(`==> Trying to log out user ${user.email}`);
        } else {
            this.logger.info('==> Trying to log out anonymous user');
        }
        res.clearCookie('access-token').status(StatusCodes.OK)
            .send();
        this.logger.info('<== Success: User logged out');
    }

    private authenticateUserForLogout(req: Request) {
        const token = req.cookies['access-token'];
        if (!token) {
            this.logger.error('User does not possess access-token cookie');
            return null;
        }

        return this.authService.handleAuthenticate(token)
            .then(requester => {
                this.logger.info(`User ${requester.email} successfully authenticated`);
                return requester;
            });
    }
}

export default AuthController;
