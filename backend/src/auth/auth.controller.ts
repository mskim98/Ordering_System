import { Controller, Post, Headers, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/user/dto/create-user.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /** 회원 가입 */
  /** authorization : Basic $token => email:password(base64 encoded) */
  @Post('register')
  registerUser(
    @Headers('authorization') token: string,
    @Body() body: CreateUserDto,
  ) {
    return this.authService.register(token, body);
  }
}
