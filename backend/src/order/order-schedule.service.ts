import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, QueryRunner, Repository } from 'typeorm';
import { Order, OrderStatus } from './entities/order.entity';

@Injectable()
export class OrderScheduleService {
  private readonly logger = new Logger(OrderScheduleService.name);
  private readonly CHUNK_SIZE = 100;
  private readonly MAX_RETRIES = 3;

  constructor(
    @InjectRepository(Order)
    private orderRepository: Repository<Order>,
    private dataSource: DataSource,
  ) {}

  /**
   * 월, 수, 금요일이 지난 직후(화, 목, 토요일 00:01)에 실행
   * '발주대기중'인 주문을 '발주중'으로 변경
   */
  @Cron('1 0 * * 2,4,6')
  async updateOrderStatus() {
    this.logger.log(
      '월수금 이후(화목토 자정) 주문 상태 업데이트 배치 작업 실행 중...',
    );

    try {
      const totalOrders = await this.orderRepository.count({
        where: { status: OrderStatus.발주대기중 },
      });

      if (totalOrders === 0) {
        this.logger.log('업데이트할 발주대기중 주문이 없습니다.');
        return;
      }

      this.logger.log(`총 ${totalOrders}개의 발주대기중 주문을 처리합니다.`);

      const totalChunks = Math.ceil(totalOrders / this.CHUNK_SIZE);
      let processedOrders = 0;

      for (let chunk = 0; chunk < totalChunks; chunk++) {
        await this.processOrder();
        processedOrders += this.CHUNK_SIZE;
        this.logger.log(
          `청크 ${chunk + 1}/${totalChunks} 처리 완료 (전체 진행상황 : ${Math.min(processedOrders, totalOrders)}/${totalOrders})`,
        );
      }

      this.logger.log(
        `발주 상태 업데이트 배치 작업 완료: 총 ${totalOrders}개 처리됨`,
      );
    } catch (error) {
      this.logger.error(
        `월수금 이후 주문 상태 업데이트 중 오류 발생: ${error.message}`,
        error.stack,
      );
    }
  }

  private async processOrder(): Promise<void> {
    let retries = 0;
    let success = false;

    while (!success && retries < this.MAX_RETRIES) {
      try {
        await this.orderChunkTransaction();
        success = true;
      } catch (error) {
        retries++;
        this.logger.warn(
          `청크 처리 실패 (시도 ${retries}/${this.MAX_RETRIES}): ${error.message}`,
        );

        if (retries >= this.MAX_RETRIES) {
          this.logger.error(`최대 재시도 횟수 초과. 청크 처리 실패`);
          throw error;
        }

        const waitTime = Math.pow(2, retries) * 1000;
        this.logger.log(`${waitTime}ms 후 재시도합니다...`);
        await new Promise((resolve) => setTimeout(resolve, waitTime));
      }
    }
  }

  private async orderChunkTransaction(): Promise<void> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const ordersToUpdate = await this.findOrdersToUpdate(
        queryRunner,
        this.CHUNK_SIZE,
      );

      if (ordersToUpdate.length === 0) {
        await queryRunner.commitTransaction();
        return;
      }

      const orderIds = ordersToUpdate.map((order) => order.id);

      const updateResult = await queryRunner.manager
        .createQueryBuilder()
        .update(Order)
        .set({ status: OrderStatus.발주중 })
        .whereInIds(orderIds)
        .execute();

      await queryRunner.commitTransaction();

      this.logger.log(
        `${updateResult.affected}개의 주문 상태가 '발주대기중'에서 '발주중'으로 업데이트되었습니다.`,
      );
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error(`트랜잭션 실패: ${error.message}`);
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  private async findOrdersToUpdate(
    queryRunner: QueryRunner,
    limit: number,
  ): Promise<Order[]> {
    return queryRunner.manager
      .createQueryBuilder(Order, 'order')
      .where('order.status = :status', { status: OrderStatus.발주대기중 })
      .orderBy('order.createdAt', 'ASC')
      .take(limit)
      .getMany();
  }
}
