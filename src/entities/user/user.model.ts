import bcrypt from 'bcrypt';
import { Model, model, Schema } from 'mongoose';

import config from '@config';
import Logger from '@utils/logger';

import { User } from './user.types';

const logger = Logger.create(__filename);

const userSchema: Schema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    roles: {
        type: [String],
        required: true
    }
}, {
    timestamps: true,
    versionKey: false
});

userSchema.set('toJSON', {
    transform: (_, returnObject) => {
        delete returnObject.password;
        returnObject.id = returnObject._id;
        delete returnObject._id;
        return returnObject;
    }
});

userSchema.pre('save', async function (next) {
    const user = this as User;
    if (!user.isModified('password')) {
        return next();
    }
    const salt = await bcrypt.genSalt(config.SALT_PASSWORD_ROUNDS);
    user.password = bcrypt.hashSync(user.password, salt);
    return next();
});

userSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
    const user = this as User;
    return bcrypt.compare(candidatePassword, user.password)
        .catch(() => {
            logger.error('comparePassword: Passwords are not equal');
            return false;
        });
};

const UserModel: Model<User> = model('User', userSchema);

export default UserModel;
