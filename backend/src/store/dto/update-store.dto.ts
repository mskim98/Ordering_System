import { PartialType } from '@nestjs/mapped-types';
import { CreateStoreDto } from './create-store.dto';
import { IsString, IsEnum, IsBoolean, IsOptional } from 'class-validator';
import { Brand } from '../entities/store.entity';

export class UpdateStoreDto extends PartialType(CreateStoreDto) {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  address?: string;

  @IsOptional()
  @IsEnum(Brand)
  brand?: Brand;

  @IsOptional()
  @IsBoolean()
  breakCondition?: boolean;

  @IsOptional()
  @IsBoolean()
  active?: boolean;
}
