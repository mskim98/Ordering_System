import { PartialType } from '@nestjs/mapped-types';
import { CreateOwnerDto } from './create-owner.dto';
import { IsNotEmpty, IsNumber, IsOptional, IsString } from 'class-validator';

export class UpdateOwnerDto extends PartialType(CreateOwnerDto) {
  @IsNotEmpty()
  @IsNumber()
  userId?: number;

  @IsNotEmpty()
  @IsNumber()
  storeId?: number;

  @IsOptional()
  @IsString()
  detail?: string;
}
