import {
  BadRequestException,
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { NextFunction, Request, Response } from 'express';
import { envVaribaleKeys } from 'src/common/const/env.const';

@Injectable()
export class TokenAuthanicator implements NestMiddleware {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}
  async use(req: Request, res: Response, next: NextFunction) {
    /// Basic $token
    /// Bearer $token
    const authHeader = req.headers['authorization'];

    /** 검증 헤더 없는 경우 패스 */
    if (!authHeader) {
      next();
      return;
    }

    /** 검증 헤더가 있는 경우 */
    try {
      /** Basic => { email, password } */
      /** Bearer => { tokenType, payload } */
      const validatedResult = await this.validateToken(authHeader);

      req.user = validatedResult;
      next();
    } catch (e) {
      throw new UnauthorizedException('토큰 검증 실패');
    }
  }

  /** 토큰 검증(Basic, Bearer) */
  validateToken(rawToken: string) {
    const { tokenType, token } = this.parseToken(rawToken);
    if (tokenType == 'basic') {
      /** Basic 인 경우 */
      /** { email, password } 객체 반환 */
      return this.basicTokenValidate(token);
    } else {
      /** Bearer 인 경우 */
      /** access 인 경우, refresh인 경우 */
      return this.bearerTokenValidate(token);
    }
  }

  /** Basic, Bearer 파싱 */
  parseToken(rawToken: string) {
    try {
      const rawSplit = rawToken.split(' ');

      if (rawSplit.length !== 2) {
        throw new Error('invalid token format');
      }

      const tokenType = rawSplit[0].toLowerCase();
      const token = rawSplit[1];

      /** 토큰 타입 검증(Basic, Baerer) */
      if (tokenType !== 'basic' && tokenType !== 'bearer') {
        throw new Error('invalid token format');
      }

      return { tokenType, token };
    } catch (e) {
      if (e.message === 'invalid token format') {
        throw new BadRequestException('잘못된 토큰 형식입니다.');
      }

      throw new BadRequestException('토큰 파싱 실패');
    }
  }

  /** Basic 토큰 검증 */
  /** 검증완료시 { email, password } 객체 반환 */
  async basicTokenValidate(rawtoken: string) {
    try {
      const decoded = Buffer.from(rawtoken, 'base64').toString('utf-8');

      /// "email:password"
      /// [email, password]
      const tokenSplit = decoded.split(':');

      if (tokenSplit.length !== 2) {
        throw new Error('login format error');
      }

      const [email, password] = tokenSplit;

      return { email, password };
    } catch (e) {
      if (e.message === 'login format error') {
        throw new BadRequestException('잘못된 로그인 형식입니다.');
      }
      // Base64 디코딩 실패
      if (e instanceof TypeError) {
        throw new BadRequestException('Base64 디코딩에 실패했습니다.');
      }
      // 기타 에러 처리
      throw new BadRequestException('Basic 토큰 검증 실패');
    }
  }

  /** Bearer 토큰 검증 */
  /** 검증 완료시 payload 반환 */
  async bearerTokenValidate(rawToken: string) {
    try {
      /** payload decoding */
      const decodedPayload = await this.jwtService.decode(rawToken);

      const bearerType = decodedPayload.type;

      /** payload로부터 토큰 type 확인 */
      if (bearerType !== 'access' && bearerType !== 'refresh') {
        throw new Error('token Type error');
      }

      /** 토큰 타입에 맞는 시크릿키 가져오기 */
      const secretKey =
        bearerType === 'refresh'
          ? envVaribaleKeys.refreshTokenSecret
          : envVaribaleKeys.accessTokenSecret;

      const payload = await this.jwtService.verifyAsync(rawToken, {
        secret: this.configService.get<string>(secretKey),
      });

      return payload;
    } catch (e) {
      if (e.message == 'token Type error') {
        throw new UnauthorizedException('잘못된 토큰 타입');
      }

      throw new UnauthorizedException('Bearer 토큰 검증 실패');
    }
  }
}
