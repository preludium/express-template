import dayjs from 'dayjs';

import TokenModel, { Token } from '@entities/token';
import { User } from '@entities/user';
import Logger from '@utils/logger';
import { signToken, verifyToken } from '@utils/middlewares';
import { TokenBundle } from '@utils/types/token';

import UserService from '../user';

class TokenService {
    private logger = Logger.create(__filename);
    private tokens = TokenModel;
    private userService = new UserService();

    public async saveNewRefreshToken(user: User, refreshToken: string) {
        await this.deleteRefreshTokenByUser(user);
        await this.createNewRefreshToken(user, refreshToken);
    }

    public async processRefreshToken(refreshToken: string) {
        const token = await this.findByHash(refreshToken);
        if (!token) {
            throw new Error('Token does not exist');
        }
        if (dayjs().isAfter(token.expiresIn)) {
            await this.deleteRefreshTokenByHash(token.hash);
            throw new Error(`Token ${token._id} expired`);
        }
        const userId = await verifyToken(refreshToken, 'REFRESH_TOKEN');
        if (token.userId !== userId) {
            throw new Error('Invalid token payload');
        }
        const user = await this.userService.getUserById(userId);
        return await this.generateTokens(user);
    }

    public async generateTokens(user: User): Promise<TokenBundle> {
        const accessToken = signToken(user, 'ACCESS_TOKEN');
        const refreshToken = signToken(user, 'REFRESH_TOKEN');
        await this.saveNewRefreshToken(user, refreshToken);
        return { accessToken, refreshToken };
    }

    public async findByHash(hash: string): Promise<Token | null> {
        return this.tokens.findOne({ hash });
    }

    public async doesTokenExist(refreshToken: string): Promise<boolean> {
        return await this.findByHash(refreshToken)
            .then(token => token !== null)
            .catch(() => {
                return false;
            });
    }

    public async deleteRefreshTokenByUser(user: User) {
        const { deletedCount } = await this.tokens.deleteOne({ userId: user._id });

        if (deletedCount > 0) {
            this.logger.info(`Deleted previous refresh token assigned to user ${user.email}`);
        }
    }

    public async deleteRefreshTokenByHash(hash: string) {
        const { deletedCount } = await this.tokens.deleteOne({ hash });

        if (deletedCount > 0) {
            this.logger.info('Deleted expired refresh token');
        }
    }

    private async createNewRefreshToken(user: User, refreshToken: string) {
        await this.tokens.create({
            userId: user._id,
            hash: refreshToken,
            expiresIn: dayjs()
                .add(7, 'd')
                .toDate()
        });

        this.logger.info('New refresh token saved in database');
    }
}

export default TokenService;
