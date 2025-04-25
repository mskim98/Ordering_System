import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Logistics } from './logistics.entity';
import {
  Column,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity('warehouses')
export class Warehouse extends TimeLineField {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column()
  active: boolean;

  @ManyToOne(() => Logistics, (logistics) => logistics.warehouses)
  @JoinColumn({ name: 'logistics_id' })
  logistics: Logistics;
}
