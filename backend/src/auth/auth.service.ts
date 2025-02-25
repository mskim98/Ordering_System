import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Role, User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { envVaribaleKeys } from 'src/common/const/env.const';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  /** 토큰 파싱 */
  parseToken(rawToken: string) {
    const rawSplit = rawToken.split(' ');

    /** 토큰 검증 */
    if (rawSplit.length !== 2) {
      throw new BadRequestException('토큰 형식이 올바르지 않습니다.');
    }

    const [tokenType, token] = rawSplit;

    /** 토큰 검증(Basic, Baerer) */
    if (tokenType !== 'Bearer' && tokenType !== 'Basic') {
      throw new BadRequestException('토큰 형식이 올바르지 않습니다.');
    }

    if (tokenType == 'Basic') {
      /** Basic 인 경우 */
      const decoded = Buffer.from(token, 'base64').toString('utf-8');
      const tokenSplit = decoded.split(':');
      const [email, password] = tokenSplit;
      return { email, password };
    } else {
      /** Bearer 인 경우 */
      const decoded = this.jwtService.decode(token);
      return { token, decoded };
    }
  }

  /** 토큰 발급 : true => refresh, false => access */
  async issueToken(user: { id: number; role: Role }, isRefreshToken: boolean) {
    const refreshTokenSecret = this.configService.get<string>(
      envVaribaleKeys.refreshTokenSecret,
    );
    const accessTokenSecret = this.configService.get<string>(
      envVaribaleKeys.accessTokenSecret,
    );

    return this.jwtService.signAsync(
      {
        sub: user.id,
        role: user.role,
        type: isRefreshToken ? 'refresh' : 'access',
      },
      {
        secret: isRefreshToken ? refreshTokenSecret : accessTokenSecret,
        expiresIn: isRefreshToken ? '24h' : 300,
      },
    );
  }

  /** 회원가입 */
  async register(rawToken: string, createUserDto: CreateUserDto) {
    const { email, password } = this.parseToken(rawToken);

    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (user) {
      throw new NotFoundException('이미 가입된 이메일입니다.');
    }

    const hash = await bcrypt.hash(
      password,
      await this.configService.get<number>(envVaribaleKeys.hashRounds),
    );

    await this.userRepository.save({
      ...createUserDto,
      email,
      password: hash,
    });

    return this.userRepository.findOne({ where: { email } });
  }

  async login(rawToken: string) {
    const { email, password } = this.parseToken(rawToken);

    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      throw new NotFoundException('잘못된 로그인 정보입니다.');
    }

    const passOk = await bcrypt.compare(password, user.password);

    if (!passOk) {
      throw new BadRequestException('잘못된 로그인 정보입니다.');
    }

    return {
      refreshToken: await this.issueToken(user, true),
      accessToken: await this.issueToken(user, false),
    };
  }

  /** 토큰 검증: 검증 성공시 payload 반환 */
  async checkToken(rawToken: string) {
    const { token, decoded } = this.parseToken(rawToken);

    try {
      /** payload로부터 토큰 type 확인 */
      if (!decoded || typeof decoded !== 'object') {
        throw new BadRequestException('유효하지 않은 토큰입니다.');
      }

      const tokenType = decoded.type;

      if (tokenType !== 'refresh' && tokenType !== 'access') {
        throw new BadRequestException('토큰이 타입이 잘못되었습니다.');
      }

      /** type에 따라 키값으로 토큰 검증 */
      const payload = await this.jwtService.verifyAsync(token, {
        secret:
          tokenType == 'refresh'
            ? this.configService.get<string>(envVaribaleKeys.refreshTokenSecret)
            : this.configService.get<string>(envVaribaleKeys.accessTokenSecret),
      });

      return payload;
    } catch (e) {
      if (e instanceof BadRequestException) {
        throw e;
      }

      if (e.name === 'TokenExpiredError') {
        throw new UnauthorizedException('토큰이 만료되었습니다.');
      } else if (e.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('유효하지 않은 토큰입니다.');
      } else {
        throw new UnauthorizedException('토큰 검증에 실패했습니다.');
      }
    }
  }

  async accessCheck(rawtoken) {
    try {
      this.checkToken(rawtoken);
      console.log('pass');
      return 'pass';
    } catch (e) {
      console.log('fail');
      return 'fail';
    }
  }
}
