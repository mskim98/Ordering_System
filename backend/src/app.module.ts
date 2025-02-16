import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { StoreModule } from './store/store.module';
import { WarehouseModule } from './warehouse/warehouse.module';
import { DeliveryModule } from './delivery/delivery.module';
import { ItemModule } from './item/item.module';
import { OrderModule } from './order/order.module';

@Module({
  imports: [UserModule, StoreModule, WarehouseModule, DeliveryModule, ItemModule, OrderModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
