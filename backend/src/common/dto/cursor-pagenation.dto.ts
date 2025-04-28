import { IsArray, IsInt, IsOptional, IsString } from 'class-validator';
import { Transform, Type } from 'class-transformer';

export class CursorPagenationDto {
  @IsString()
  @IsOptional()
  cursor?: string;

  @IsOptional()
  @Transform(({ value }) => {
    // 값이 이미 배열이면 그대로 반환
    if (Array.isArray(value)) {
      return value;
    }
    // 문자열이면 배열로 변환
    if (typeof value === 'string') {
      return [value];
    }
    // 기본값
    return ['id_DESC'];
  })
  @IsArray()
  @IsString({ each: true })
  order: string[] = ['id_DESC'];

  @IsInt()
  @IsOptional()
  @Type(() => Number)
  take?: number = 3;
}
