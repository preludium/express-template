import 'module-alias/register';
import 'source-map-support/register';
import config from '@config';
import controllers from '@controller';

import App from './app';

const app = new App(
    controllers,
    config.PORT
);

app.listen();
