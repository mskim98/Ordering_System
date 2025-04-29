import { Injectable, LoggerService as NestLoggerService } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as winston from 'winston';
import * as DailyRotateFile from 'winston-daily-rotate-file';
import * as path from 'path';

@Injectable()
export class LoggerService implements NestLoggerService {
  private readonly logger: winston.Logger;
  private readonly userLogger: winston.Logger;
  private readonly batchLogger: winston.Logger;

  constructor(private configService: ConfigService) {
    const logDir = this.configService.get<string>('LOG_DIR', 'logs');
    const env = this.configService.get<string>('NODE_ENV', 'development');

    // 공통 로깅 포맷 설정
    const logFormat = winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.errors({ stack: true }),
      winston.format.splat(),
      winston.format.json(),
    );

    // 콘솔 로깅 설정
    const consoleOptions = {
      level: env === 'production' ? 'info' : 'debug',
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple(),
      ),
    };

    // 시스템 로그 설정 (에러 및 일반 로그)
    this.logger = winston.createLogger({
      format: logFormat,
      transports: [
        new winston.transports.Console(consoleOptions),
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
    });

    // 유저 활동 로그 설정
    this.userLogger = winston.createLogger({
      format: logFormat,
      transports: [
        new DailyRotateFile({
          dirname: path.join(logDir, 'user'),
          filename: 'user-activity-%DATE%.log',
          datePattern: 'YYYY-MM-DD',
          maxSize: '20m',
          maxFiles: '30d',
        }),
      ],
    });

    // 배치 작업 로그 설정
    this.batchLogger = winston.createLogger({
      format: logFormat,
      transports: [
        new DailyRotateFile({
          dirname: path.join(logDir, 'batch'),
          filename: 'batch-%DATE%.log',
          datePattern: 'YYYY-MM-DD',
          maxSize: '20m',
          maxFiles: '30d',
        }),
      ],
    });
  }

  /* 로거 레벨별 인터페이스 구현 */
  log(message: string, context?: string): void {
    this.logger.info(message, { context });
  }

  error(message: string, trace?: string, context?: string): void {
    this.logger.error(message, { trace, context });
  }

  warn(message: string, context?: string): void {
    this.logger.warn(message, { context });
  }

  debug(message: string, context?: string): void {
    this.logger.debug(message, { context });
  }

  verbose(message: string, context?: string): void {
    this.logger.verbose(message, { context });
  }

  /* 사용자 활동 로깅 */
  logUserActivity(userId: string, action: string, details: any): void {
    this.userLogger.info('사용자 활동', {
      userId,
      action,
      details,
    });
  }

  /** API 호출 로깅 */
  logApiCall(
    method: string,
    path: string,
    statusCode: number,
    responseTime: number,
    userId?: string,
  ): void {
    this.logger.info('API 호출', {
      method,
      path,
      statusCode,
      responseTime,
      userId: userId || 'anonymous',
    });
  }

  /** 배치 작업 로깅 */
  logBatchJob(jobName: string, status: string, details?: any): void {
    this.batchLogger.info('배치 작업', {
      jobName,
      status,
      details,
      timestamp: new Date().toISOString(),
    });
  }

  /** 보안 관련 로깅 */
  logSecurity(event: string, details: any, userId?: string): void {
    this.logger.warn('보안 이벤트', {
      event,
      details,
      userId: userId || 'unknown',
      timestamp: new Date().toISOString(),
    });
  }
}
