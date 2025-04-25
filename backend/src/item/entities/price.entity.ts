import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Item } from 'src/item/entities/item.entity';
import {
  Column,
  Entity,
  JoinColumn,
  OneToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity()
export class Price extends TimeLineField {
  @PrimaryGeneratedColumn()
  id: number;

  @OneToOne(() => Item, (item) => item.price, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'item_id' })
  item: Item;

  @Column()
  priceIn: number;

  @Column({ nullable: true })
  priceOut: number;

  @Column({ nullable: true })
  margin: number;
}
