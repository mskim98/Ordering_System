import { Controller, Post, Body, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { Public } from './decorator/public.decorator';
import { Permission, RBAC } from './decorator/rbac.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /** 회원 가입 */
  /** Basic Token 요구 */
  @Post('register')
  @RBAC([Permission.USER_REGISTER])
  registerUser(@Body() body: CreateUserDto) {
    return this.authService.register(body);
  }

  /** 로그인(검증 및 토큰 발급) */
  /** Basic Token 요구 */
  @Post('login')
  @Public()
  async loginUser(@Request() req) {
    return await this.authService.login(req.user);
  }

  /** 토큰 재발급 */
  /** Bearer Token(refresh token) 요구 */
  @Post('token/newToken')
  @Public()
  async newAccessToken(@Request() req) {
    return { accessToken: await this.authService.issueToken(req.user, false) };
  }
}
