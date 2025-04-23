import {
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  RequestTimeoutException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { timeout, catchError } from 'rxjs/operators';
import { TimeoutError } from 'rxjs';

export class TimeoutInterceptor implements NestInterceptor {
  constructor(private readonly timeoutValue: number = 30000) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      /** 요청 시작시 타이머 시작 */
      timeout(this.timeoutValue),
      catchError((err) => {
        if (err instanceof TimeoutError) {
          throw new RequestTimeoutException('요청 처리 시간이 초과되었습니다.');
        }
        throw err;
      }),
    );
  }
}
