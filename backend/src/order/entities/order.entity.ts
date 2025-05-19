import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  OneToMany,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { OrderItem } from './orderItem.entity';
import { TimeLineField } from 'src/common/entity/timeline.entity';
import { User } from 'src/user/entities/user.entity';

export enum OrderStatus {
  작성중 = '작성중',
  발주대기중 = '발주대기중',
  발주중 = '발주중',
  확인중 = '확인중',
  발주완료 = '발주완료',
  취소 = '취소',
  수동발주 = '수동발주',
}
@Entity()
export class Order extends TimeLineField {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => User, (user) => user.orders, {
    onDelete: 'SET NULL',
    nullable: true,
  })
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  total: number;

  @Column()
  storeId: number;

  @Column()
  storeName: string;

  @Column({
    type: 'enum',
    enum: [
      OrderStatus.작성중,
      OrderStatus.발주대기중,
      OrderStatus.발주중,
      OrderStatus.확인중,
      OrderStatus.발주완료,
      OrderStatus.취소,
      OrderStatus.수동발주,
    ],
    default: OrderStatus.작성중,
  })
  status: OrderStatus;

  @OneToMany(() => OrderItem, (orderItem) => orderItem.order, {
    cascade: true,
  })
  orderItems: OrderItem[];
}
