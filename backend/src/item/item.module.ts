import { Module } from '@nestjs/common';
import { ItemService } from './item.service';
import { ItemController } from './item.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Item } from './entities/item.entity';
import { Price } from './entities/price.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Item, Price])],
  controllers: [ItemController],
  providers: [ItemService],
})
export class ItemModule {}
