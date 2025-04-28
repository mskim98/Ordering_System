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
    enum: ['작성중', '발주중', '확인중', '발주완료', '취소'],
    default: '작성중',
  })
  status: '작성중' | '발주중' | '확인중' | '발주완료' | '취소';

  @OneToMany(() => OrderItem, (orderItem) => orderItem.order, {
    cascade: true,
  })
  orderItems: OrderItem[];
}
