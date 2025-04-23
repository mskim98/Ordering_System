import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Item extends TimeLineField {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column()
  type: string;

  @Column()
  useCondition: boolean;

  @Column()
  specification: string;
}
