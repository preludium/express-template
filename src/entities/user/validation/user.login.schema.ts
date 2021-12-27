import * as yup from 'yup';

import { passwordValidator } from '@utils/validators';

export const responseMessage = 'Email or password is invalid';

export const loginUserSchema = yup.object().shape({
    email: yup.string()
        .email(responseMessage),
    ...passwordValidator({ customResponseMessage: responseMessage })
});
