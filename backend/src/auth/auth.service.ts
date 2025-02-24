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
    private readonly configServcie: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  /** 회원가입 */
  parseBasicToken(rawToken: string) {
    /** [Basic, token] */
    const basicSplit = rawToken.split(' ');

    if (basicSplit.length !== 2) {
      throw new BadRequestException('토큰 포멧이 올바르지 않습니다.');
    }

    const [basic, token] = basicSplit;

    /** email:password */
    /** decoding(base64) */
    const decoded = Buffer.from(token, 'base64').toString('utf-8');

    /** [email, password] */
    const tokenSplit = decoded.split(':');

    if (tokenSplit.length !== 2) {
      throw new BadRequestException('잘못된 로그인 정보입니다.');
    }

    const [email, password] = tokenSplit;

    return {
      email,
      password,
    };
  }

  async issueToken(user: { id: number; role: Role }, isRefreshToken: boolean) {
    const refreshTokenSecret = this.configServcie.get<string>(
      envVaribaleKeys.refreshTokenSecret,
    );
    const accessTokenSecret = this.configServcie.get<string>(
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

  async userCheck(email: string) {
    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (!user) {
      throw new NotFoundException('잘못된 로그인 포멧입니다.');
    }
  }

  /** 회원가입 */
  async register(rawToken: string, createUserDto: CreateUserDto) {
    const { email, password } = this.parseBasicToken(rawToken);

    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (user) {
      throw new NotFoundException('이미 가입된 이메일입니다.');
    }

    const hash = await bcrypt.hash(
      password,
      await this.configServcie.get<number>(envVaribaleKeys.hashRounds),
    );

    await this.userRepository.save({
      ...createUserDto,
      email,
      password: hash,
    });

    return this.userRepository.findOne({ where: { email } });
  }

  async login(rawToken: string) {
    const { email, password } = this.parseBasicToken(rawToken);

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
}
