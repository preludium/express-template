import jwt from 'jsonwebtoken';

import config from '@config';
import { User } from '@entities/user';

import Logger from '../logger';

interface JWTPayload {
    id: string;
    iat: number;
}

const logger = Logger.create(__filename);

export const signToken = (
    object: User,
    keyName: 'ACCESS_TOKEN' | 'REFRESH_TOKEN',
    options?: jwt.SignOptions | undefined
) => {
    const privateKey = config[`${keyName}_PRIVATE_KEY`];
    const expiresIn = config[`${keyName}_VALIDITY`];

    return jwt.sign({ id: object._id }, privateKey, {
        ...(options && options),
        expiresIn,
        algorithm: 'RS256'
    });
};

export const verifyToken = async (
    token: string,
    keyName: 'ACCESS_TOKEN' | 'REFRESH_TOKEN'
): Promise<string> => {
    const publicKey = config[`${keyName}_PUBLIC_KEY`];

    try {
        const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] }) as JWTPayload;
        return payload.id;
    } catch (error: any) {
        logger.error(error.message);
        throw new Error('Token expired');
    }
};
