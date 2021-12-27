import * as yup from 'yup';

import { Roles } from '@utils/constants';
import { passwordValidator } from '@utils/validators';

export const updateUserSchema = yup.object().shape({
    email: yup.string()
        .email('Not a valid email'),
    ...passwordValidator(),
    roles: yup.array(
        yup.mixed<Roles>()
            .oneOf(Object.values(Roles), 'Wrong roles format')
    )
});
