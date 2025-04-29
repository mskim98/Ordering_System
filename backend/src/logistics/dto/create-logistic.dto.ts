import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsPhoneNumber,
  IsString,
} from 'class-validator';

export class CreateLogisticDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsPhoneNumber('KR')
  @IsOptional()
  phone: string;

  @IsEmail()
  @IsOptional()
  email: string;
}
