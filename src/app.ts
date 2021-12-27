import compression from 'compression';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { Application } from 'express';
import helmet from 'helmet';
import mongoose from 'mongoose';
import morgan from 'morgan';

import config from '@config';
import AuthController from '@controller/auth';
import Logger from '@utils/logger';
import { errorMiddleware } from '@utils/middlewares';
import { Controller } from '@utils/types/controller';

class App {
    public express: Application;
    public port: number;
    private logger = Logger.create(__filename);

    constructor(controllers: Controller[], port: number) {
        this.express = express();
        this.port = port;

        this.initialiseDatabaseConnection();
        this.initialiseMiddleware();
        this.initialiseControllers(controllers);
        this.initialiseErrorHandling();
    }

    private initialiseMiddleware(): void {
        this.express.use(helmet());
        this.express.use(cors());
        this.express.use(cookieParser());
        this.express.use(morgan('[:date[web]] :remote-addr :url :method', { immediate: true }));
        this.express.use(express.json());
        this.express.use(express.urlencoded({ extended: false }));
        this.express.use(compression());
    }

    private initialiseControllers(controllers: Controller[]) {
        const authController = new AuthController();
        this.express.use('', authController.router);
        controllers.forEach((controller: Controller) => {
            this.express.use('/api', controller.router);
        });
    }

    private initialiseErrorHandling() {
        this.express.use(errorMiddleware);
    }

    private initialiseDatabaseConnection() {
        this.logger.info('Mongo connecting...');
        mongoose.connect(config.DB_URI)
            .then(() => {
                this.logger.info('MongoDB Connected');
            })
            .catch(err => {
                this.logger.error(err.message);
                process.exit(1);
            });
    }

    public listen(): void {
        this.express.listen(this.port, async () => {
            this.logger.info(`App listening on the port ${this.port}`);
        });
    }
}

export default App;
