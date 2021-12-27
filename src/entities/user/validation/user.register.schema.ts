import * as yup from 'yup';

import { passwordValidator } from '@utils/validators';

export const registerUserSchema = yup.object().shape({
    email: yup.string()
        .email('Not a valid email')
        .required('Email is required'),
    ...passwordValidator({ required: true }),
    confirmPassword: yup.string()
        .required('Password confirmation is required')
        .oneOf([ yup.ref('password'), null ], 'Passwords must match')
})
    .required();
