import { Global, Module } from '@nestjs/common';
import { LoggerService } from './logger.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { BatchLoggerService } from './batch-logger.service';
import * as path from 'path';
import * as winston from 'winston';
import * as DailyRotateFile from 'winston-daily-rotate-file';
import { WinstonModule } from 'nest-winston';
import { LoggingInterceptor } from './logging.interceptor';
import { HttpExceptionFilter } from './http-exception.filter';

@Global()
@Module({
  imports: [
    ConfigModule,
    WinstonModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const logDir = configService.get<string>('LOG_DIR', 'logs');
        const env = configService.get<string>('NODE_ENV', 'development');

        /** 로그 포맷 설정 */
        const logFormat = winston.format.combine(
          winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
          winston.format.errors({ stack: true }),
          winston.format.splat(),
          winston.format.json(),
        );

        return {
          format: logFormat,
          transports: [
            new winston.transports.Console({
              level: env === 'production' ? 'info' : 'debug',
              format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple(),
              ),
            }),
            new DailyRotateFile({
              level: 'error',
              dirname: path.join(logDir, 'system'),
              filename: 'error-%DATE%.log',
              datePattern: 'YYYY-MM-DD',
              maxSize: '20m',
              maxFiles: '14d',
            }),
            new DailyRotateFile({
              level: 'info',
              dirname: path.join(logDir, 'system'),
              filename: 'combined-%DATE%.log',
              datePattern: 'YYYY-MM-DD',
              maxSize: '20m',
              maxFiles: '14d',
            }),
          ],
        };
      },
    }),
  ],
  providers: [
    LoggerService,
    BatchLoggerService,
    LoggingInterceptor,
    HttpExceptionFilter,
  ],
  exports: [
    LoggerService,
    BatchLoggerService,
    LoggingInterceptor,
    HttpExceptionFilter,
  ],
})
export class LoggerModule {}
