import {
  IsEnum,
  IsString,
  IsNotEmpty,
  IsBoolean,
  IsOptional,
} from 'class-validator';
import { Brand } from '../entities/store.entity';

export class CreateStoreDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  address: string;

  @IsNotEmpty()
  @IsEnum(Brand)
  brand: Brand;

  @IsOptional()
  @IsBoolean()
  holidayCondition?: boolean;

  @IsOptional()
  @IsBoolean()
  active?: boolean;
}
