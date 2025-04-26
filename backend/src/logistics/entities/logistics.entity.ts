import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Warehouse } from './warehouse.entity';
import { PrimaryGeneratedColumn, Column, Entity, OneToMany } from 'typeorm';

@Entity('logistics')
export class Logistics extends TimeLineField {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column({ nullable: true })
  phone?: string;

  @Column({ nullable: true })
  email?: string;

  @OneToMany(() => Warehouse, (warehouse) => warehouse.logistics, {
    cascade: true,
  })
  warehouse: Warehouse[];
}
