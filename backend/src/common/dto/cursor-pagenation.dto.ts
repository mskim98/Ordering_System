import { IsArray, IsInt, IsOptional, IsString } from 'class-validator';

export class CursorPagenationDto {
  @IsString()
  @IsOptional()
  cursor?: string;

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  order: string[] = ['id_DESC'];

  @IsInt()
  @IsOptional()
  take?: number = 3;
}
