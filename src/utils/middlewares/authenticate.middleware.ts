import jwt from 'jsonwebtoken';
import { ObjectId } from 'mongoose';

import config from '@config';
import { User } from '@entities/user';

import Logger from '../logger';

interface JWTPayload {
    id: ObjectId;
    iat: number;
}

const logger = Logger.create(__filename);

export const signToken = (
    object: User,
    keyName: 'ACCESS_TOKEN' | 'REFRESH_TOKEN',
    options?: jwt.SignOptions | undefined
) => {
    logger.info(keyName);
    const privateKey = config[`${keyName}_PRIVATE_KEY`];
    const expiresIn = config[`${keyName}_VALIDITY`];
    logger.info(expiresIn);
    return jwt.sign({ id: object._id }, privateKey, {
        ...(options && options),
        expiresIn,
        algorithm: 'RS256'
    });
};

export const verifyToken = async (
    token: string,
    keyName: 'ACCESS_TOKEN' | 'REFRESH_TOKEN'
): Promise<ObjectId> => {
    const publicKey = config[`${keyName}_PUBLIC_KEY`];

    try {
        const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] }) as JWTPayload;
        return payload.id;
    } catch (error: any) {
        logger.error(error.message);
        throw new Error('Token expired');
    }
};
