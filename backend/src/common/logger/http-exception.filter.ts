import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { LoggerService } from './logger.service';

// User 인터페이스 정의
interface User {
  id: string;
  [key: string]: any;
}

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  constructor(private readonly loggerService: LoggerService) {}

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const errorResponse =
      exception instanceof HttpException
        ? exception.getResponse()
        : { message: '서버 내부 오류가 발생했습니다.' };

    const errorMessage =
      typeof errorResponse === 'object' && 'message' in errorResponse
        ? errorResponse.message
        : errorResponse;

    const errorStack = exception instanceof Error ? exception.stack : '';

    // 사용자 정보 가져오기
    const user = (request as any).user as User | undefined;
    const userId = user?.id || (user?.email ? user.email : 'unknown');

    // 상세 에러 정보 로깅
    this.loggerService.error(
      `[예외] ${request.method} ${request.url} ${status} - ${errorMessage}`,
      errorStack,
      'HttpExceptionFilter',
    );

    // 보안 관련 에러라면 별도로 보안 로그에 기록
    if (status === HttpStatus.UNAUTHORIZED || status === HttpStatus.FORBIDDEN) {
      this.loggerService.logSecurity(
        '인증/인가 실패',
        {
          path: request.url,
          method: request.method,
          ip: request.ip,
          headers: request.headers,
        },
        userId,
      );
    }

    // 클라이언트에 응답
    response.status(status).json({
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message: errorMessage,
    });
  }
}
