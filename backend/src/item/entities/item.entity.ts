import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Price } from 'src/item/entities/price.entity';
import { Logistics } from 'src/logistics/entities/logistics.entity';
import { OrderItem } from 'src/order/entities/orderItem.entity';
import {
  Column,
  Entity,
  JoinColumn,
  ManyToOne,
  OneToMany,
  OneToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';

export enum ItemType {
  냉장식품 = '냉장식품',
  냉동식품 = '냉동식품',
  소스 = '소스',
  일회용품 = '일회용품',
  비품 = '비품',
  기타 = '기타',
}
@Entity()
export class Item extends TimeLineField {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column({
    type: 'enum',
    enum: ItemType,
  })
  type: ItemType;

  @Column()
  useCondition: boolean;

  @Column()
  specification: string;

  @OneToOne(() => Price, (price) => price.item, {
    cascade: true,
    onDelete: 'CASCADE',
  })
  price: Price;

  @ManyToOne(() => Logistics, (logistics) => logistics.item, {
    onDelete: 'SET NULL',
    nullable: true,
  })
  @JoinColumn({ name: 'logisticsId' })
  logistics: Logistics;

  @OneToMany(() => OrderItem, (orderItem) => orderItem.item)
  orderItems: OrderItem[];
}
