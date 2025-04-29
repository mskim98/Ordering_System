import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { LoggerService } from './logger.service';
import { Request, Response } from 'express';

// User 인터페이스 정의
interface User {
  id: string;
  [key: string]: any;
}

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  constructor(private readonly loggerService: LoggerService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const now = Date.now();
    const request = context.switchToHttp().getRequest<Request>();
    const { method, path, body } = request;

    // API 호출 시작 로깅
    this.loggerService.debug(`[요청] ${method} ${path}`, 'HttpRequest');

    // 민감한 정보 제거
    this.sanitizeBody(body);

    return next.handle().pipe(
      tap({
        next: () => {
          const response = context.switchToHttp().getResponse<Response>();
          const statusCode = response.statusCode;
          const responseTime = Date.now() - now;

          // 요청 처리 완료 후 user 객체를 가져옴 (이 시점에는 auth 미들웨어 처리 완료)
          const user = (request as any).user as User | undefined;
          const userId = user?.id || (user?.email ? user.email : 'anonymous');

          /** API 호출 로깅 */
          this.loggerService.logApiCall(
            method,
            path,
            statusCode,
            responseTime,
            userId,
          );

          /** 응답 정보 로깅 (디버그 레벨) */
          if (statusCode >= 400) {
            this.loggerService.debug(
              `[오류 응답] ${method} ${path} ${statusCode} ${responseTime}ms`,
              'HttpResponse',
            );
          } else {
            this.loggerService.debug(
              `[성공 응답] ${method} ${path} ${statusCode} ${responseTime}ms`,
              'HttpResponse',
            );
          }
        },
        error: (error: any) => {
          const response = context.switchToHttp().getResponse<Response>();
          const statusCode = response.statusCode || 500;
          const responseTime = Date.now() - now;

          // 오류 발생 시에도 user 정보 가져오기
          const user = (request as any).user as User | undefined;
          const userId = user?.id || (user?.email ? user.email : 'anonymous');

          /** 에러 로깅 */
          this.loggerService.error(
            `[예외] ${method} ${path} ${statusCode} ${responseTime}ms - ${error.message}`,
            error.stack,
            'HttpException',
          );

          /** API 호출 로깅 (에러 케이스) */
          this.loggerService.logApiCall(
            method,
            path,
            statusCode,
            responseTime,
            userId,
          );
        },
      }),
    );
  }

  /** 민감한 정보(비밀번호, 토큰 등) 제거 */
  private sanitizeBody(body: any): any {
    if (!body) return {};

    const sanitized = { ...body };
    const sensitiveFields = [
      'password',
      'token',
      'accessToken',
      'refreshToken',
    ];

    sensitiveFields.forEach((field) => {
      if (field in sanitized) {
        sanitized[field] = '[REDACTED]';
      }
    });

    return sanitized;
  }
}
