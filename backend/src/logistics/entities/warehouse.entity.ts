import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Logistics } from './logistics.entity';
import {
  Column,
  Entity,
  JoinColumn,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Store } from 'src/store/entities/store.entity';

@Entity('warehouse')
export class Warehouse extends TimeLineField {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column()
  active: boolean;

  @Column()
  address: string;

  @Column()
  phone: string;
  @ManyToOne(() => Logistics, (logistics) => logistics.warehouse, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'logisticsId' })
  logistics: Logistics;

  @OneToMany(() => Store, (store) => store.warehouse, {
    onDelete: 'CASCADE',
  })
  store: Store;
}
