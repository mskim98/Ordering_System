import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { CreateOrderDto, OrderItemDto } from './dto/create-order.dto';
import { UpdateOrderDto } from './dto/update-order.dto';
import { Order, OrderStatus } from './entities/order.entity';
import { OrderItem } from './entities/orderItem.entity';
import { Item } from 'src/item/entities/item.entity';
import {
  QueryRunner,
  Repository,
  OptimisticLockVersionMismatchError,
} from 'typeorm';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { CommonService } from 'src/common/common.service';

@Injectable()
export class OrderService {
  constructor(
    @InjectRepository(Order)
    private orderRepository: Repository<Order>,
    private readonly commonService: CommonService,
  ) {}

  async createWithRetry(
    dto: CreateOrderDto,
    queryRunner: QueryRunner,
    maxRetries = 3,
  ): Promise<Order> {
    let lastError: any;
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await this.create(dto, queryRunner);
      } catch (error) {
        if (
          error.name === 'OptimisticLockVersionMismatchError' ||
          error.code === '40001'
        ) {
          lastError = error;
          await new Promise((res) => setTimeout(res, 100 * Math.pow(2, i)));
          continue;
        }
        throw error;
      }
    }
    throw lastError;
  }

  private async create(
    Dto: CreateOrderDto,
    queryRunner: QueryRunner,
  ): Promise<Order> {
    try {
      const { userId, storeId, storeName, orderItems } = Dto;
      const newOrder = await queryRunner.manager.create(Order, {
        user: { id: userId },
        storeId,
        storeName,
        status: OrderStatus.작성중,
        total: 0,
      });

      const savedOrder = await queryRunner.manager.save(newOrder);

      const orderedItems = await Promise.all(
        orderItems.map((item) =>
          this.createOrderItemWithRetry(item, savedOrder, queryRunner),
        ),
      );

      savedOrder.total = orderedItems.reduce(
        (acc, item) => acc + item.total,
        0,
      );

      return queryRunner.manager.save(Order, savedOrder);
    } catch (error) {
      if (error.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 품목입니다.');
      }
      throw new InternalServerErrorException('주문 생성 실패');
    }
  }

  private async createOrderItemWithRetry(
    Dto: OrderItemDto,
    order: Order,
    queryRunner: QueryRunner,
    maxRetries = 3,
  ): Promise<OrderItem> {
    let lastError: Error;

    for (let i = 0; i < maxRetries; i++) {
      try {
        return await this.createOrderItem(Dto, order, queryRunner);
      } catch (error) {
        if (
          error instanceof OptimisticLockVersionMismatchError ||
          error.code === '40001'
        ) {
          lastError = error;
          // 지수 백오프 적용
          await new Promise((resolve) =>
            setTimeout(resolve, Math.pow(2, i) * 100),
          );
          continue;
        }
        throw error;
      }
    }

    throw lastError;
  }

  private async createOrderItem(
    Dto: OrderItemDto,
    order: Order,
    queryRunner: QueryRunner,
  ): Promise<OrderItem> {
    const { itemId, quantity } = Dto;

    try {
      const itemWithPrice = await queryRunner.manager
        .createQueryBuilder(Item, 'item')
        .leftJoinAndSelect('item.price', 'price')
        .where('item.id = :id', { id: itemId })
        .setLock('pessimistic_read')
        .getOne();

      if (!itemWithPrice) {
        throw new NotFoundException(`존재하지 않은 품목아이디:${itemId}`);
      }

      const newOrderItem = await queryRunner.manager.create(OrderItem, {
        order: { id: order.id },
        item: { id: itemId },
        name: itemWithPrice.name,
        quantity,
        price: itemWithPrice.price?.priceOut || 0,
        total: (itemWithPrice.price?.priceOut || 0) * quantity,
      });

      return await queryRunner.manager.save(OrderItem, newOrderItem);
    } catch (error) {
      if (
        error instanceof OptimisticLockVersionMismatchError ||
        error.code === '40001'
      ) {
        throw new ConflictException(
          '품목 정보가 수정중입니다. 다시 시도해주세요.',
        );
      }
      throw error;
    }
  }

  async findAll(DTO: CursorPagenationDto) {
    try {
      const qb = this.orderRepository.createQueryBuilder('order');

      // orderItems와 user 관계를 함께 로드
      return await this.commonService.CursorPagenationParamsQb(qb, DTO, [
        'orderItems',
        'user',
      ]);
    } catch (error) {
      throw new InternalServerErrorException(
        `주문 조회 실패: ${error.message}`,
      );
    }
  }

  async findMy(DTO: CursorPagenationDto, userId: number) {
    try {
      const qb = this.orderRepository.createQueryBuilder('order');
      qb.where('order.userId = :userId', { userId });

      return await this.commonService.CursorPagenationParamsQb(qb, DTO);
    } catch (error) {
      throw new InternalServerErrorException(
        `주문 조회 실패: ${error.message}`,
      );
    }
  }

  async findOne(id: number) {
    try {
      const order = await this.orderRepository.findOne({
        where: { id },
        relations: ['orderItems'],
      });

      if (!order) {
        throw new NotFoundException(`주문 ID ${id}를 찾을 수 없습니다`);
      }

      return order;
    } catch {
      throw new InternalServerErrorException('주문 조회 실패');
    }
  }

  async update(
    id: number,
    updateOrderDto: UpdateOrderDto,
    queryRunner: QueryRunner,
  ) {
    try {
      const order = await queryRunner.manager.findOne(Order, {
        where: { id },
        lock: { mode: 'pessimistic_read' },
      });

      if (!order) {
        throw new NotFoundException('not exist');
      }

      const { storeId, storeName, status, orderItems } = updateOrderDto;

      if (storeId) order.storeId = storeId;
      if (storeName) order.storeName = storeName;
      if (status) order.status = status;

      if (orderItems && orderItems.length > 0) {
        await queryRunner.manager.delete(OrderItem, { order: { id } });

        const orderedItems = await Promise.all(
          orderItems.map((item) =>
            this.createOrderItem(item, order, queryRunner),
          ),
        );

        order.total = orderedItems.reduce((acc, item) => acc + item.total, 0);
      }

      await queryRunner.manager.save(Order, order);

      return await queryRunner.manager.findOne(Order, {
        where: { id },
        relations: ['orderItems'],
      });
    } catch (error) {
      if (error.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 주문입니다.');
      }
      throw new InternalServerErrorException('주문 업데이트 실패');
    }
  }

  async remove(id: number, queryRunner: QueryRunner) {
    try {
      const order = await queryRunner.manager.findOne(Order, {
        where: { id },
      });

      if (!order) {
        throw new NotFoundException(`주문 ID ${id}를 찾을 수 없습니다`);
      }

      await queryRunner.manager.remove(Order, order);
      return { id, success: true, message: '주문이 성공적으로 삭제되었습니다' };
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerErrorException(
        `주문 삭제 실패: ${error.message}`,
      );
    }
  }
}
