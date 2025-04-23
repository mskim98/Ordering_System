import { PartialType } from '@nestjs/mapped-types';
import { CreateItemDto } from './create-item.dto';
import { IsString, IsBoolean, IsOptional } from 'class-validator';
import { Column } from 'typeorm';

export class UpdateItemDto extends PartialType(CreateItemDto) {
  @IsString()
  @IsOptional()
  @Column()
  name?: string;

  @IsString()
  @IsOptional()
  @Column()
  type?: string;

  @IsBoolean()
  @IsOptional()
  @Column()
  useCondition?: boolean = true;

  @IsString()
  @IsOptional()
  @Column()
  specification?: string;
}
