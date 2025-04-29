import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Role, User } from './entities/user.entity';
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

  /** 유저 확인 공통 로직 */
  async IDCheck(id) {
    /// 데이터베이스의 유저 존재 확인
    const user = await this.userRepository.findOne({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('해당 유저가 존재하지 않습니다.');
    }

    return user;
  }

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
  async findOne(id: number, user) {
    /** 유저 본인의 아이디만 조회 가능 */
    if (user.role !== Role.admin && id !== user.sub) {
      throw new ForbiddenException('권한이 없습니다.');
    }
    /** 조회한 유저 정보 반환 */
    return await this.IDCheck(id);
  }

  /** id 기반 유저 정보 수정 */
  async update(id: number, updateUserDto: UpdateUserDto) {
    /// 유저 확인
    this.IDCheck(id);

    /// 유저 정보 저장
    await this.userRepository.update({ id }, updateUserDto);

    /// 조회한 새로운 유저 정보 반환
    return this.userRepository.findOne({
      where: { id },
    });
  }

  /** id 기반 유저 삭제 */
  async remove(id: number) {
    const user = await this.IDCheck(id);
    await this.userRepository.delete(user.id);
    return { message: '유저 삭제 완료' };
  }
}
