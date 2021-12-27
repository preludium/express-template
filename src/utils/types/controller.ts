import express from 'express';
import * as core from 'express-serve-static-core';

import { User } from '@entities/user';

export type Query = core.Query;

export type Params = core.ParamsDictionary;

export type Request<ReqBody = any, ReqQuery = Query, URLParams extends Params = core.ParamsDictionary>
    = express.Request<URLParams, any, ReqBody, ReqQuery>;

interface ResponseLocals {
    user: User;
}

export type ApiResponse<ResBody = any> = express.Response<ResBody, ResponseLocals>;
export type Response<ResBody = any> = express.Response<ResBody>;

export interface Controller {
    readonly path: string;
    readonly router: express.Router;
}
