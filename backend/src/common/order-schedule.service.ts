import { Injectable } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Order } from 'src/order/entities/order.entity';

@Injectable()
export class OrderScheduleService {
  constructor(
    @InjectRepository(Order)
    private orderRepository: Repository<Order>,
  ) {}

  // 매일 오후 1시에 실행
  @Cron('0 13 * * *')
  async updateOrderStatus() {
    console.log('주문 상태 업데이트 배치 실행:', new Date());

    try {
      /** '발주대기중' 상태인 주문들을 '발주중'으로 변경 */
      const result = await this.orderRepository.update(
        { status: '발주대기중' },
        { status: '발주중' },
      );

      console.log(`${result.affected} 개의 주문 상태 업데이트 완료`);
    } catch (error) {
      console.error('주문 상태 업데이트 실패:', error);
    }
  }
}
