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
    try {
      const qb = this.ownerRepository.createQueryBuilder('owner');

      return await this.commonService.CursorPagenationParamsQb(qb, Dto);
    } catch (error) {
      throw new InternalServerErrorException(
        '점주 - 점포 조회 중 오류가 발생했습니다.',
      );
    }
  }

  async findOne(id: number) {
    try {
      const owner = await this.ownerRepository.findOne({
        where: { id },
      });

      if (!owner) {
        throw new NotFoundException('not exist');
      }

      return owner;
    } catch (error) {
      if (error.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 점주 - 점포 입니다.');
      }
      throw new InternalServerErrorException(
        '점주 - 점포 조회 중 오류가 발생했습니다.',
      );
    }
  }

  async update(ownerId: number, updateDto: any, queryRunner: QueryRunner) {
    try {
      const owner = await queryRunner.manager.exists(Owner, {
        where: { id: ownerId },
      });

      if (!owner) {
        throw new NotFoundException('not exist');
      }

      if (updateDto.userId) {
        const user = await queryRunner.manager.exists(User, {
          where: { id: updateDto.userId },
        });
        if (!user) {
          throw new NotFoundException('not exist');
        }
      }

      if (updateDto.storeId) {
        const store = await queryRunner.manager.exists(Store, {
          where: { id: updateDto.storeId },
        });
        if (!store) {
          throw new NotFoundException('not exist');
        }
      }

      await queryRunner.manager.update(Owner, ownerId, updateDto);
      return await queryRunner.manager.findOne(Owner, {
        where: { id: ownerId },
      });
    } catch (e) {
      if (e.message === 'not exist') {
        throw new NotFoundException(
          '참조하는 사용자 또는 점포가 존재하지 않습니다.',
        );
      }
      throw new InternalServerErrorException(
        '점주 정보 업데이트 중 오류가 발생했습니다.',
      );
    }
  }

  async remove(id: number) {
    const owner = await this.findOne(id);

    await this.ownerRepository.remove(owner);
    return { message: '점주 - 점포 삭제 완료' };
  }
}
