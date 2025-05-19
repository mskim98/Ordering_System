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

  @Column({ type: 'decimal', precision: 10, scale: 0 })
  priceIn: number;

  @Column({ type: 'decimal', precision: 10, scale: 0 })
  priceOut: number;

  @Column({ type: 'decimal', precision: 5, scale: 2, default: 0 })
  margin: number;
}
