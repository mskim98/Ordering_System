import {
  IsArray,
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Min,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

export class OrderItemDto {
  @IsNotEmpty()
  @IsInt()
  itemId: number;

  @IsNotEmpty()
  @IsInt()
  @Min(1)
  quantity: number;
}

export class UpdateOrderDto {
  @IsOptional()
  @IsInt()
  storeId?: number;

  @IsOptional()
  @IsString()
  storeName?: string;

  @IsOptional()
  @IsEnum(['작성중', '발주중', '확인중', '발주완료', '취소'])
  status?: '작성중' | '발주중' | '확인중' | '발주완료' | '취소';

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => OrderItemDto)
  orderItems?: OrderItemDto[];
}
