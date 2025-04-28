import { Exclude } from 'class-transformer';
import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Order } from 'src/order/entities/order.entity';
import { Owner } from 'src/owner/entities/owner.entity';
import {
  Column,
  Entity,
  OneToMany,
  OneToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';

/** 사용자 계층 */
export enum Role {
  /** 관리자 */
  admin,
  /** 협력사 */
  partner,
  /** 점주 */
  owner,
}
@Entity()
export class User extends TimeLineField {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column()
  phone: string;

  @Column({ enum: Role })
  role: Role;

  @Column()
  email: string;

  @Column({ length: 60 })
  @Exclude({
    toPlainOnly: true,
  })
  password: string;

  @OneToOne(() => Owner, (owner) => owner.user, { cascade: true })
  owner: Owner;

  @OneToMany(() => Order, (order) => order.user)
  orders: Order[];
}
