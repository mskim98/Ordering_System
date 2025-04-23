import { IsString, IsNotEmpty, IsBoolean, IsOptional } from 'class-validator';
import { Column } from 'typeorm';

export class CreateItemDto {
  @IsString()
  @IsNotEmpty()
  @Column()
  name: string;

  @IsString()
  @IsNotEmpty()
  @Column()
  type: string;

  @IsBoolean()
  @IsNotEmpty()
  @Column()
  useCondition: boolean = true;

  @IsString()
  @IsOptional()
  @Column()
  specification?: string;
}
