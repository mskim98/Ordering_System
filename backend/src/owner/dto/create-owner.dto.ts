import { IsNotEmpty, IsNumber, IsOptional, IsString } from 'class-validator';

export class CreateOwnerDto {
  @IsNotEmpty()
  @IsNumber()
  userId: number;

  @IsNotEmpty()
  @IsNumber()
  storeId: number;

  @IsOptional()
  @IsString()
  detail?: string;
}
