import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { QueryRunner, Repository } from 'typeorm';
import { Order, OrderStatus } from './entities/order.entity';

@Injectable()
export class OrderScheduleService {
  private readonly logger = new Logger(OrderScheduleService.name);

  constructor(
    @InjectRepository(Order)
    private orderRepository: Repository<Order>,
  ) {}

  /**
   * 월, 수, 금요일이 지난 직후(화, 목, 토요일 00:01)에 실행
   * '발주대기중'인 주문을 '발주중'으로 변경
   */
  @Cron('1 0 * * 2,4,6')
  async updateOrderStatusAfterMWF() {
    this.logger.log(
      '월수금 이후(화목토 자정) 주문 상태 업데이트 배치 작업 실행 중...',
    );

    try {
      const result = await this.orderRepository.update(
        {
          status: OrderStatus.발주대기중,
        },
        { status: OrderStatus.발주중 },
      );

      if (result.affected > 0) {
        this.logger.log(
          `${result.affected}개의 주문 상태가 '발주대기중'에서 '발주중'으로 업데이트되었습니다.`,
        );
      } else {
        this.logger.log('업데이트할 발주대기중 주문이 없습니다.');
      }
    } catch (error) {
      this.logger.error(
        `월수금 이후 주문 상태 업데이트 중 오류 발생: ${error.message}`,
        error.stack,
      );
    }
  }
}
