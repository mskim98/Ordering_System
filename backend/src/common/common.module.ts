import { Module, Global } from '@nestjs/common';
import { CommonService } from './common.service';
import { OrderScheduleService } from './order-schedule.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Order } from 'src/order/entities/order.entity';

@Global()
@Module({
  imports: [TypeOrmModule.forFeature([Order])],
  providers: [CommonService, OrderScheduleService],
  exports: [CommonService],
})
export class CommonModule {}
