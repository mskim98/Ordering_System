import {
  IsNotEmpty,
  IsString,
  IsEnum,
  IsEmail,
  IsOptional,
} from 'class-validator';
import { Role } from '../entities/user.entity';

export class CreateUserDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsNotEmpty()
  @IsString()
  phone: string;

  @IsNotEmpty()
  @IsEnum(Role)
  role: Role;

  @IsNotEmpty()
  @IsString()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;
}
