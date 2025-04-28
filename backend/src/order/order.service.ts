import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { CreateOrderDto, OrderItemDto } from './dto/create-order.dto';
import { UpdateOrderDto } from './dto/update-order.dto';
import { Order } from './entities/order.entity';
import { OrderItem } from './entities/orderItem.entity';
import { Item } from 'src/item/entities/item.entity';
import { QueryRunner, Repository } from 'typeorm';
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

  async create(Dto: CreateOrderDto, queryRunner: QueryRunner): Promise<Order> {
    try {
      const { userId, storeId, storeName, orderItems } = Dto;
      const newOrder = await queryRunner.manager.create(Order, {
        user: { id: userId },
        storeId,
        storeName,
        status: '작성중',
        total: 0,
      });

      const savedOrder = await queryRunner.manager.save(newOrder);

      const orderedItems = await Promise.all(
        orderItems.map((item) =>
          this.createOrderItem(item, savedOrder, queryRunner),
        ),
      );

      savedOrder.total = orderedItems.reduce(
        (acc, item) => acc + item.total,
        0,
      );

      return queryRunner.manager.save(Order, savedOrder);
    } catch (error) {
      console.log(error);
      throw new InternalServerErrorException('주문 생성 실패');
    }
  }

  private async createOrderItem(
    Dto: OrderItemDto,
    order: Order,
    queryRunner: QueryRunner,
  ): Promise<OrderItem> {
    const { itemId, quantity } = Dto;

    const item = await queryRunner.manager.findOne(Item, {
      where: { id: itemId },
      relations: ['price'],
    });

    if (!item) {
      throw new NotFoundException(`Item with ID ${itemId} not found`);
    }

    const newOrderItem = await queryRunner.manager.create(OrderItem, {
      order: { id: order.id },
      item: { id: itemId },
      name: item.name,
      quantity,
      price: item.price?.priceOut || 0,
      total: (item.price?.priceOut || 0) * quantity,
    });

    return queryRunner.manager.save(OrderItem, newOrderItem);
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
        relations: ['orderItems'],
      });

      if (!order) {
        throw new NotFoundException(`주문 ID ${id}를 찾을 수 없습니다`);
      }

      const { storeId, storeName, status, orderItems } = updateOrderDto;

      if (storeId) {
        order.storeId = storeId;
      }

      if (storeName) {
        order.storeName = storeName;
      }

      if (status) {
        order.status = status;
      }

      if (orderItems) {
        const orderedItems = await Promise.all(
          orderItems.map((item) =>
            this.createOrderItem(item, order, queryRunner),
          ),
        );

        order.total = orderedItems.reduce((acc, item) => acc + item.total, 0);
      }

      return queryRunner.manager.save(Order, order);
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerErrorException(
        `주문 업데이트 실패: ${error.message}`,
      );
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
