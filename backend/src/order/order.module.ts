import { Module } from '@nestjs/common';
import { OrderService } from './order.service';
import { OrderController } from './order.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Item } from 'src/item/entities/item.entity';
import { Order } from './entities/order.entity';
import { OrderItem } from './entities/orderItem.entity';
import { CommonModule } from 'src/common/common.module';
import { OrderScheduleService } from './order-schedule.service';

@Module({
  imports: [TypeOrmModule.forFeature([Order, OrderItem, Item]), CommonModule],
  controllers: [OrderController],
  providers: [OrderService, OrderScheduleService],
  exports: [OrderService],
})
export class OrderModule {}
