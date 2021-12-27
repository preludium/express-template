import { Schema } from 'mongoose';

export interface Token extends Object {
    id: Schema.Types.ObjectId;
    expiresIn: number;
}
