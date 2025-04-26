import {
  IsBoolean,
  IsNotEmpty,
  IsOptional,
  IsPhoneNumber,
  IsString,
} from 'class-validator';

export class CreateWarehouseDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsBoolean()
  @IsOptional()
  active: boolean = true;

  @IsString()
  @IsNotEmpty()
  address: string;

  @IsPhoneNumber('KR')
  @IsOptional()
  phone: string;
}
