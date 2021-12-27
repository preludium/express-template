import { NextFunction, Request, Response } from 'express';
import StatusCodes from 'http-status-codes';

import HttpException from '../exceptions/http.exception';
import Logger from '../logger';

// eslint-disable-next-line max-params
export const errorMiddleware = (err: HttpException, req: Request, res: Response, next: NextFunction) => {
    const logger = Logger.create(__filename);
    const status = err.status ?? StatusCodes.INTERNAL_SERVER_ERROR;
    const message = err.message ?? 'Something went wrong';
    logger.error(`<== Failure: Status ${status} | ${message}`);
    return res.status(status).send(message);
};
