import { PartialType } from '@nestjs/mapped-types';
import { CreateItemDto } from './create-item.dto';
import {
  IsString,
  IsBoolean,
  IsOptional,
  IsEnum,
  IsInt,
  Min,
} from 'class-validator';
import { ItemType } from '../entities/item.entity';

export class UpdateItemDto extends PartialType(CreateItemDto) {
  @IsString()
  @IsOptional()
  name?: string;

  @IsEnum(ItemType)
  @IsOptional()
  type?: ItemType;

  @IsBoolean()
  @IsOptional()
  useCondition?: boolean;

  @IsString()
  @IsOptional()
  specification?: string;

  @IsInt()
  @IsOptional()
  @Min(0)
  priceIn?: number;

  @IsInt()
  @IsOptional()
  @Min(0)
  margin?: number;

  @IsInt()
  @IsOptional()
  @Min(0)
  priceOut?: number;
}
