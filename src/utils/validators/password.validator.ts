import * as yup from 'yup';

interface PasswordValidatorOptions {
    customResponseMessage?: string;
    required?: boolean;
}

// eslint-disable-next-line complexity
const regularValidator = (customResponseMessage?: string) => yup.string()
    .min(5, customResponseMessage ?? 'Password is too short')
    .max(20, customResponseMessage ?? 'Password is too long')
    .matches(
        /[a-z]+/,
        customResponseMessage ?? 'Password must contain at least one lower case letter'
    )
    .matches(
        /[A-Z]+/,
        customResponseMessage ?? 'Password must contain at least one upper case letter'
    )
    .matches(
        /[0-9]+/,
        customResponseMessage ?? 'Password must contain at least one digit'
    )
    .matches(
        /[!@#$%^&*)(+=._-]+/,
        customResponseMessage ?? 'Password must contain at least one special character'
    );

export const passwordValidator = (options?: PasswordValidatorOptions) => {
    return {
        password: options?.required
            ? regularValidator(options?.customResponseMessage)
                .required(options?.customResponseMessage ?? 'Password is required')
            : regularValidator(options?.customResponseMessage)
    };
};
