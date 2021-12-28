import { Model, model, Schema } from 'mongoose';

import Logger from '@utils/logger';

import { Token } from './token.types';

const logger = Logger.create(__filename);

const tokenSchema: Schema<Token> = new Schema({
    userId: {
        type: String,
        required: true,
        unique: true
    },
    hash: {
        type: String,
        required: true,
        unique: true
    },
    expiresIn: Date
}, {
    versionKey: false
});

tokenSchema.set('toJSON', {
    transform: (_, returnObject) => {
        delete returnObject.userId;
        delete returnObject.hash;
        return returnObject;
    }
});

// userSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
//     const user = this as User;
//     return bcrypt.compare(candidatePassword, user.password)
//         .catch(() => {
//             logger.error('comparePassword: Passwords are not equal');
//             return false;
//         });
// };

const TokenModel: Model<Token> = model('Token', tokenSchema);

export default TokenModel;
