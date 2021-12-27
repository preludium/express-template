import { Request, Response, NextFunction } from 'express';
import StatusCodes from 'http-status-codes';
import { ObjectSchema, ValidationError } from 'yup';

import Logger from '@utils/logger';

export const validateRequestMiddleware = (schema: ObjectSchema<any>) => {
    const logger = Logger.create(__filename);
    return (req: Request, res: Response, next: NextFunction) => schema.validate(req.body)
        .then(() => {
            next();
        })
        .catch((error: ValidationError) => {
            logger.error(`${req.originalUrl} validation failed`);
            res.status(StatusCodes.BAD_REQUEST)
                .send(error.errors[0]);
        });
};
