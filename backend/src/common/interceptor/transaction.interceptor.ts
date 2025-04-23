import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { catchError, Observable, tap } from 'rxjs';
import { DataSource } from 'typeorm';

@Injectable()
export class TransactionInterceptor implements NestInterceptor {
  constructor(private readonly datasource: DataSource) {}
  async intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Promise<Observable<any>> {
    /** 앤드포인트 실행전 트랜잭션 시작(queryRunner 생성) */
    const req = context.switchToHttp().getRequest();

    const queryRunner = this.datasource.createQueryRunner();

    await queryRunner.connect();
    await queryRunner.startTransaction();
    req.queryRunner = queryRunner;

    /** 앤드포인트 실행후 트랜잭션 커밋 또는 롤백 */
    return next.handle().pipe(
      tap(async () => {
        await queryRunner.commitTransaction();
        await queryRunner.release();
      }),
      catchError(async (e) => {
        await queryRunner.rollbackTransaction();
        await queryRunner.release();
        throw e;
      }),
    );
  }
}
