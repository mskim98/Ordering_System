import { TimeLineField } from 'src/common/entity/timeline.entity';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

/// 사용자 계층
export enum Role {
  admin, /// 관리자
  partner, /// 협력사
  owner, /// 점주
}
@Entity()
export class User extends TimeLineField {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  u_name: string;

  @Column()
  u_phone: number;

  @Column({ enum: Role })
  role: Role;

  @Column()
  email: string;

  @Column()
  password: string;
}
