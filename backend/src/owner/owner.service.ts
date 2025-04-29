import {
  BadRequestException,
  Injectable,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import { CreateOwnerDto } from './dto/create-owner.dto';
import { QueryRunner, Repository } from 'typeorm';
import { Owner } from './entities/owner.entity';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { CommonService } from 'src/common/common.service';
import { User } from 'src/user/entities/user.entity';
import { Store } from 'src/store/entities/store.entity';

@Injectable()
export class OwnerService {
  constructor(
    @InjectRepository(Owner)
    private readonly ownerRepository: Repository<Owner>,
    private readonly commonService: CommonService,
  ) {}

  async create(createOwnerDto: CreateOwnerDto, queryRunner: QueryRunner) {
    const { userId, storeId } = createOwnerDto;

    const owner = await queryRunner.manager.findOne(Owner, {
      where: { userId, storeId },
    });

    if (owner) {
      throw new BadRequestException('이미 존재하는 점주입니다.');
    }

    const newOwner = await queryRunner.manager.save(Owner, {
      ...createOwnerDto,
    });

    return queryRunner.manager.findOne(Owner, {
      where: { id: newOwner.id },
    });
  }

  async findAll(Dto: CursorPagenationDto) {
    const qb = this.ownerRepository.createQueryBuilder('owner');

    const { results, nextCursor } =
      await this.commonService.CursorPagenationParamsQb(qb, Dto);

    return { results, nextCursor };
  }

  async findOne(id: number) {
    let owner;

    try {
      owner = await this.ownerRepository.findOne({
        where: { id },
      });
    } catch {
      throw new InternalServerErrorException(
        '점주 - 점포 조회 중 오류가 발생했습니다.',
      );
    }

    if (!owner) {
      throw new NotFoundException('존재하지 않는 점주 - 점포 입니다.');
    }

    return owner;
  }

  async update(ownerId: number, updateDto: any, queryRunner: QueryRunner) {
    try {
      if (updateDto.userId) {
        const user = await queryRunner.manager.findOne(User, {
          where: { id: updateDto.userId },
        });
        if (!user) {
          throw new BadRequestException('존재하지 않는 사용자입니다.');
        }
      }

      if (updateDto.storeId) {
        const store = await queryRunner.manager.findOne(Store, {
          where: { id: updateDto.storeId },
        });
        if (!store) {
          throw new BadRequestException('존재하지 않는 점포입니다.');
        }
      }

      await queryRunner.manager.update(Owner, ownerId, updateDto);
      return await queryRunner.manager.findOne(Owner, {
        where: { id: ownerId },
      });
    } catch (e) {
      if (e.code === '23503') {
        throw new BadRequestException(
          '참조하는 사용자 또는 점포가 존재하지 않습니다.',
        );
      }
      throw new InternalServerErrorException(
        '점주 정보 업데이트 중 오류가 발생했습니다.',
      );
    }
  }

  async remove(id: number) {
    try {
      const owner = await this.findOne(id);

      await this.ownerRepository.remove(owner);
      return { message: '점주 - 점포 삭제 완료' };
    } catch (e) {
      if (e.message === '존재하지 않는 점주 - 점포 입니다.') {
        throw new NotFoundException('존재하지 않는 점주 - 점포 입니다.');
      }
      throw new InternalServerErrorException(
        '점주 삭제 중 오류가 발생했습니다.',
      );
    }
  }
}
