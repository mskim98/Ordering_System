import { Controller, Post, Headers, Body, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/user/dto/create-user.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /** 회원 가입 */
  @Post('register')
  registerUser(@Request() req, @Body() body: CreateUserDto) {
    return this.authService.register(req.user, body);
  }

  /** 로그인(검증 및 토큰 발급) */
  @Post('login')
  async loginUser(@Request() req) {
    return await this.authService.login(req.user);
  }

  /** 토큰 재발급 */
  @Post('token/newToken')
  async newAccessToken(@Request() req) {
    return { accessToken: await this.authService.issueToken(req.user, false) };
  }

  @Post('token/access')
  async checkAccessToken(@Request() req) {
    return await this.authService.accessTest(req.user);
  }
}
