import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

export enum Brand {
  /** 빨간어묵포차 */
  빨간어묵포차 = '빨간어묵포차',
  /** 바다해어묵 */
  바다해어묵 = '바다해어묵',
}

@Entity()
export class Store extends TimeLineField {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column()
  address: string;

  @Column({ enum: Brand })
  brand: Brand;

  /** 2,4주차 휴점 여부 */
  @Column({ default: false })
  holidayCondition: boolean;

  /** 점포 활성화 여부 */
  @Column({ default: false })
  active: boolean;
}
