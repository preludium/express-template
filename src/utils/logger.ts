import dayjs from 'dayjs';
import path from 'path';
import { createLogger, format, transports } from 'winston';

class Logger {
    public static create(fileName: string) {
        return createLogger({
            format: format.combine(
                format.label({ label: path.basename(fileName) }),
                format.timestamp(),
                format.colorize(),
                this.getCustomFormat()
            ),
            transports: [new transports.Console()]
        });
    }

    private static getCustomFormat() {
        return format.printf(({ level, message, label }) =>
            `[${dayjs().format('YYYY-MM-DD HH:mm:ss')}] ${level} <${label}>: ${message}`);
    }
}

export default Logger;
