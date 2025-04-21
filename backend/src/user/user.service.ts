import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  /// 유저 확인 공통 로직
  async dbCheck(id) {
    /// 데이터베이스의 유저 존재 확인
    const user = await this.userRepository.findOne({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('해당 유저가 존재하지 않습니다.');
    }

    return user;
  }

  /// 사용자 생성 로직
  async create(createUserDto: CreateUserDto) {
    await this.userRepository.save(createUserDto);
  }

  /// 전체 유저 조회
  findAll() {
    return this.userRepository.find();
  }

  /// id 기반 특정 유저 조회
  async findOne(id: number) {
    /// 조회한 유저 정보 반환
    return this.dbCheck(id);
  }

  async update(id: number, updateUserDto: UpdateUserDto) {
    /// 유저 확인
    this.dbCheck(id);

    /// 유저 정보 저장
    await this.userRepository.update({ id }, updateUserDto);

    /// 조회한 새로운 유저 정보 반환
    return this.userRepository.findOne({
      where: { id },
    });
  }

  async remove(id: number) {
    await this.userRepository.delete(id);
  }
}
