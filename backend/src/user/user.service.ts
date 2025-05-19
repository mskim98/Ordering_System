import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { envVaribaleKeys } from 'src/common/const/env.const';
import { ConfigService } from '@nestjs/config';
import { CommonService } from 'src/common/common.service';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly commonService: CommonService,
  ) {}

  /** 회원가입 */
  async register(createUserDto: CreateUserDto) {
    try {
      const { email, password } = createUserDto;
      const user = await this.userRepository.findOne({
        where: { email },
      });

      if (user) {
        throw new Error('existing');
      }

      /** password 암호화 */
      const hash = await bcrypt.hash(
        password,
        await this.configService.get<number>(envVaribaleKeys.hashRounds),
      );

      /** 사용자 데이터 저장 */
      const newUser = await this.userRepository.save({
        ...createUserDto,
        password: hash,
      });

      return newUser;
    } catch (e) {
      if (e.message === 'existing') {
        throw new BadRequestException('이미 가입된 이메일입니다.');
      }

      throw new BadRequestException('사용자 생성 실패');
    }
  }

  /** 유저 조회 테스트 */
  async test() {
    return await this.userRepository.find({
      relations: ['owner'],
    });
  }

  /** 전체 유저 조회 */
  async findAll(Dto: CursorPagenationDto) {
    try {
      const qb = this.userRepository.createQueryBuilder('user');

      /** 페이지네이션 - owner 관계 포함 */
      return await this.commonService.CursorPagenationParamsQb(
        qb,
        Dto,
        'owner',
      );
    } catch (error) {
      throw new BadRequestException(`전체 유저 조회 실패: ${error.message}`);
    }
  }

  /** id 기반 특정 유저 조회 */
  async findOne(id: number) {
    const user = await this.userRepository.findOne({
      where: { id },
      relations: ['owner'],
    });

    if (!user) {
      throw new NotFoundException('해당 유저가 존재하지 않습니다.');
    }

    return user;
  }

  /** id 기반 유저 정보 수정 */
  async update(id: number, updateUserDto: UpdateUserDto) {
    const exist = await this.userRepository.exists({
      where: { id },
    });

    if (!exist) {
      throw new NotFoundException('해당 유저가 존재하지 않습니다.');
    }

    await this.userRepository.update({ id }, updateUserDto);

    return this.userRepository.findOne({
      where: { id },
      relations: ['owner'],
    });
  }

  /** id 기반 유저 삭제 */
  async remove(id: number) {
    const user = await this.userRepository.findOne({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('해당 유저가 존재하지 않습니다.');
    }
    await this.userRepository.delete(user.id);
    return { message: '유저 삭제 완료' };
  }
}
