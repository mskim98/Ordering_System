import { PartialType } from '@nestjs/mapped-types';
import { CreateLogisticDto } from './create-logistic.dto';
import { IsString, IsPhoneNumber, IsOptional, IsEmail } from 'class-validator';

export class UpdateLogisticDto extends PartialType(CreateLogisticDto) {
  @IsString()
  @IsOptional()
  name?: string;

  @IsPhoneNumber('KR')
  @IsOptional()
  phone?: string;

  @IsEmail()
  @IsOptional()
  email?: string;
}
