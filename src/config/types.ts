export interface Config {
    PORT: number;
    DB_URI: string;
    SALT_PASSWORD_ROUNDS: number;
    ACCESS_TOKEN_VALIDITY: string;
    REFRESH_TOKEN_VALIDITY: string;
    ACCESS_TOKEN_PUBLIC_KEY: string;
    ACCESS_TOKEN_PRIVATE_KEY: string;
    REFRESH_TOKEN_PUBLIC_KEY: string;
    REFRESH_TOKEN_PRIVATE_KEY: string;
}
