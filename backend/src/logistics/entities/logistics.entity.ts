import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Warehouse } from './warehouse.entity';
import { PrimaryGeneratedColumn, Column, Entity, OneToMany } from 'typeorm';

@Entity('logistics')
export class Logistics extends TimeLineField {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  type: string;

  @Column()
  phone: string;

  @Column()
  email: string;

  @OneToMany(() => Warehouse, (warehouse) => warehouse.logistics)
  warehouses: Warehouse[];
}
