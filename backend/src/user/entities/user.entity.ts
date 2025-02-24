import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

/**
 * 사용자 계층
 */
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

  @Column({ length: 255 })
  password: string;
}
