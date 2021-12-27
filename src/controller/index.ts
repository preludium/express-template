import { Controller } from '@utils/types/controller';

import UserController from './user';

const controllers: Controller[] = [
    new UserController()
];

export default controllers;
