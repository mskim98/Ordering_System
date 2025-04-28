import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Warehouse } from './warehouse.entity';
import { PrimaryGeneratedColumn, Column, Entity, OneToMany } from 'typeorm';
import { Item } from 'src/item/entities/item.entity';

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

  @OneToMany(() => Item, (item) => item.logistics, {
    cascade: true,
  })
  item: Item[];
}
