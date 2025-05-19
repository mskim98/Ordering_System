import { IsNotEmpty, IsNumber } from 'class-validator';

export class SetStoreWarehouseDto {
  @IsNumber()
  @IsNotEmpty()
  storeId: number;

  @IsNumber()
  @IsNotEmpty()
  warehouseId: number;
}
