import { Injectable } from '@nestjs/common';
import { LoggerService } from './logger.service';

@Injectable()
export class BatchLoggerService {
  constructor(private readonly loggerService: LoggerService) {}

  /**
   * 배치 작업 시작 로깅
   * @param jobName 배치 작업 이름
   * @param params 배치 작업 파라미터
   */
  startJob(jobName: string, params?: any): void {
    this.loggerService.logBatchJob(jobName, 'started', {
      params,
      startTime: new Date().toISOString(),
    });
    this.loggerService.log(`배치 작업 시작: ${jobName}`, 'BatchService');
  }

  /**
   * 배치 작업 완료 로깅
   * @param jobName 배치 작업 이름
   * @param result 배치 작업 결과
   * @param startTime 배치 작업 시작 시간
   */
  completeJob(jobName: string, result: any, startTime?: Date): void {
    const endTime = new Date();
    const duration = startTime ? endTime.getTime() - startTime.getTime() : null;

    this.loggerService.logBatchJob(jobName, 'completed', {
      result,
      endTime: endTime.toISOString(),
      duration: duration ? `${duration}ms` : undefined,
    });

    this.loggerService.log(
      `배치 작업 완료: ${jobName}${duration ? ` (소요시간: ${duration}ms)` : ''}`,
      'BatchService',
    );
  }

  /**
   * 배치 작업 실패 로깅
   * @param jobName 배치 작업 이름
   * @param error 에러 객체
   * @param startTime 배치 작업 시작 시간
   */
  failJob(jobName: string, error: Error, startTime?: Date): void {
    const endTime = new Date();
    const duration = startTime ? endTime.getTime() - startTime.getTime() : null;

    this.loggerService.logBatchJob(jobName, 'failed', {
      error: {
        message: error.message,
        stack: error.stack,
      },
      endTime: endTime.toISOString(),
      duration: duration ? `${duration}ms` : undefined,
    });

    this.loggerService.error(
      `배치 작업 실패: ${jobName} - ${error.message}${duration ? ` (소요시간: ${duration}ms)` : ''}`,
      error.stack,
      'BatchService',
    );
  }

  /**
   * 배치 작업 진행 상황 로깅
   * @param jobName 배치 작업 이름
   * @param progress 진행률 (0-100)
   * @param details 추가 정보
   */
  progressJob(jobName: string, progress: number, details?: any): void {
    this.loggerService.logBatchJob(jobName, 'progress', {
      progress: `${progress}%`,
      details,
      timestamp: new Date().toISOString(),
    });

    if (progress % 10 === 0) {
      // 10% 단위로만 일반 로그에 기록
      this.loggerService.log(
        `배치 작업 진행 중: ${jobName} (${progress}%)`,
        'BatchService',
      );
    }
  }

  /**
   * 배치 작업의 중요 단계 로깅
   * @param jobName 배치 작업 이름
   * @param step 단계 이름
   * @param details 추가 정보
   */
  stepCompleted(jobName: string, step: string, details?: any): void {
    this.loggerService.logBatchJob(jobName, `step_${step}`, {
      step,
      details,
      timestamp: new Date().toISOString(),
    });

    this.loggerService.log(
      `배치 작업 단계 완료: ${jobName} - ${step}`,
      'BatchService',
    );
  }
}
