import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { envVaribaleKeys } from 'src/common/const/env.const';
import { CreateUserDto } from 'src/user/dto/create-user.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configServcie: ConfigService,
  ) {}

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

  async userCheck(email: string) {
    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (!user) {
      throw new NotFoundException('잘못된 로그인 정보입니다.');
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
}
