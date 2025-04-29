import {
  IsString,
  IsNotEmpty,
  IsBoolean,
  IsOptional,
  IsEnum,
  IsInt,
  Min,
  IsNumber,
} from 'class-validator';
import { ItemType } from '../entities/item.entity';

export class CreateItemDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsEnum(ItemType)
  @IsNotEmpty()
  type: ItemType;

  @IsBoolean()
  @IsOptional()
  useCondition?: boolean = true;

  @IsString()
  @IsOptional()
  specification?: string;

  @IsInt()
  @IsOptional()
  @Min(0)
  priceIn?: number = 0;

  @IsInt()
  @IsOptional()
  @Min(0)
  priceOut?: number;

  @IsNumber()
  @IsOptional()
  @Min(0)
  margin?: number;
}
