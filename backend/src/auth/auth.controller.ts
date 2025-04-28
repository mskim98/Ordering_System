import { Controller, Post, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from './decorator/public.decorator';
import { ApiBasicAuth } from '@nestjs/swagger';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /** 로그인(검증 및 토큰 발급) */
  /** Basic Token 요구 */
  @Post('login')
  @ApiBasicAuth('Basic-auth')
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
