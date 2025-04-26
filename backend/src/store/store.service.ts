import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateStoreDto } from './dto/create-store.dto';
import { UpdateStoreDto } from './dto/update-store.dto';
import { QueryRunner, Repository } from 'typeorm';
import { Store } from './entities/store.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';
import { CommonService } from 'src/common/common.service';

@Injectable()
export class StoreService {
  constructor(
    @InjectRepository(Store)
    private readonly storeRepository: Repository<Store>,
    private readonly commonService: CommonService,
  ) {}

  async create(createStoreDto: CreateStoreDto, queryRunner: QueryRunner) {
    try {
      const name = createStoreDto.name;
      const store = await queryRunner.manager.findOne(Store, {
        where: { name },
      });

      if (store) {
        throw new Error('exist');
      }

      const newStore = await queryRunner.manager.save(Store, {
        ...createStoreDto,
      });

      return newStore;
    } catch (e) {
      if (e.message === 'exist') {
        throw new BadRequestException('이미 존재하는 점포입니다.');
      }
      throw new BadRequestException('점포 생성 실패');
    }
  }

  async findAll(Dto: CursorPagenationDto) {
    const qb = this.storeRepository.createQueryBuilder('store');

    const { results, nextCusor } =
      await this.commonService.CursorPagenationParamsQb(qb, Dto);

    return { results, nextCusor };
  }

  async findOne(id: number) {
    try {
      const store = await this.storeRepository.findOne({
        where: { id },
      });

      if (!store) {
        throw new NotFoundException('존재하지 않는 점포입니다.');
      }

      return store;
    } catch (e) {
      throw new BadRequestException('점포 조회 실패');
    }
  }

  async update(
    id: number,
    updateStoreDto: UpdateStoreDto,
    queryRunner: QueryRunner,
  ) {
    try {
      const store = await queryRunner.manager.findOne(Store, {
        where: { id },
      });

      if (!store) {
        throw new BadRequestException('존재하지 않는 점포입니다.');
      }

      await queryRunner.manager.update(
        Store,
        { id },
        {
          ...updateStoreDto,
        },
      );

      return await queryRunner.manager.findOne(Store, {
        where: { id },
      });
    } catch (e) {
      throw new BadRequestException('점포 수정 실패');
    }
  }

  async remove(id: number, queryRunner: QueryRunner) {
    const store = await queryRunner.manager.findOne(Store, {
      where: { id },
    });

    if (!store) {
      throw new BadRequestException('존재하지 않는 점포입니다.');
    }

    const deleted = await queryRunner.manager.delete(Store, { id });

    if (deleted.affected === 0) {
      throw new BadRequestException('점포 삭제 실패');
    }

    return { message: '점포 삭제 완료' };
  }
}
