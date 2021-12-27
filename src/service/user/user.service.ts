import UserModel, { User, UserRequest } from '@entities/user';
import { wrongId } from '@utils/constants';

class UserService {
    public getAllUsers(): Promise<User[]> {
        return UserModel.find({})
            .catch(error => {
                throw new Error(error.message);
            });
    }

    public getUserById(userId: string): Promise<User> {
        return UserModel.findOne({ _id: userId })
            .then(user => {
                if (user === null) {
                    throw new Error(wrongId);
                }
                return user;
            })
            .catch(error => {
                throw new Error(error.message);
            });
    }

    public updateById(userId: string, user: UserRequest): Promise<User> {
        return UserModel.findOneAndUpdate({ _id: userId }, user, { new: true })
            .then(updatedUser => {
                if (!updatedUser) {
                    throw new Error(wrongId);
                }
                return updatedUser;
            })
            .catch(error => {
                if (error.codeName) {
                    throw new Error(error.codeName);
                }
                throw new Error(error.message);
            });
    }

    public deleteById(userId: string) {
        return UserModel.deleteOne({ _id: userId })
            .catch(error => {
                throw new Error(error.message);
            });
    }
}

export default UserService;
