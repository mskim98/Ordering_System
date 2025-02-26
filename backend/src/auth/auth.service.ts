import {
  BadRequestException,
  Injectable,
  NotFoundException,
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
  async register(info, createUserDto: CreateUserDto) {
    try {
      const { email, password } = info;
      const user = await this.userRepository.findOne({
        where: { email },
      });

      if (user) {
        throw new Error('existing email');
      }

      /** password 암호화 */
      const hash = await bcrypt.hash(
        password,
        await this.configService.get<number>(envVaribaleKeys.hashRounds),
      );

      /** 사용자 데이터 저장 */
      await this.userRepository.save({
        ...createUserDto,
        email,
        password: hash,
      });

      return this.userRepository.findOne({ where: { email } });
    } catch (e) {
      if (e.message === 'exisiting email') {
        throw new BadRequestException('이미 가입된 이메일입니다.');
      }

      throw new BadRequestException('사용자 생성 실패');
    }
  }

  /** 로그인 */
  async login(info) {
    try {
      const { email, password } = info;

      /** 사용자 검색(email) */
      const user = await this.userRepository.findOne({ where: { email } });

      if (!user) {
        throw new Error('invalid user information');
      }

      const passwordCheck = await bcrypt.compare(password, user.password);

      if (!passwordCheck) {
        throw new Error('invalid user information');
      }

      return {
        refreshToken: await this.issueToken(user, true),
        accessToken: await this.issueToken(user, false),
      };
    } catch (e) {
      throw new BadRequestException('잘못된 로그인 정보입니다.');
    }
  }

  async accessTest(info) {
    return info;
  }
}
