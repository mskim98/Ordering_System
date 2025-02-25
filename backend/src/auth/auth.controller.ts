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

  /** 로그인(검증 및 토큰 발급) */
  @Post('login')
  loginUser(@Headers('authorization') token: string) {
    return this.authService.login(token);
  }

  /** 토큰 재발급 */
  @Post('token/newToken')
  async newAccessToken(@Headers('authorization') token: string) {
    const payload = await this.authService.checkToken(token);

    return { accessToken: await this.authService.issueToken(payload, false) };
  }

  @Post('token/access')
  async checkAccessToken(@Headers('authorization') token: string) {
    return await this.authService.checkToken(token);
  }
}
