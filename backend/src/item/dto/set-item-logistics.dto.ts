import { IsNotEmpty, IsNumber } from 'class-validator';

export class SetItemLogisticsDto {
  @IsNumber()
  @IsNotEmpty()
  itemId: number;

  @IsNumber()
  @IsNotEmpty()
  logisticsId: number;
}
