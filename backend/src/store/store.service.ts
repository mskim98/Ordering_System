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
import { SetStoreWarehouseDto } from './dto/update-store-warehouse.dto';
import { Warehouse } from 'src/logistics/entities/warehouse.entity';
import console from 'console';

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
    try {
      const qb = this.storeRepository.createQueryBuilder('store');

      return await this.commonService.CursorPagenationParamsQb(
        qb,
        Dto,
        'warehouse',
      );
    } catch (error) {
      throw new BadRequestException('점포 조회 실패');
    }
  }

  async findOne(id: number) {
    const store = await this.storeRepository.findOne({
      where: { id },
      relations: ['warehouse'],
    });

    if (!store) {
      throw new NotFoundException('존재하지 않는 점포입니다.');
    }

    return store;
  }

  async update(
    id: number,
    updateStoreDto: UpdateStoreDto,
    queryRunner: QueryRunner,
  ) {
    try {
      const store = await queryRunner.manager.exists(Store, {
        where: { id },
      });

      if (!store) {
        throw new Error('not exist');
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
        relations: ['warehouse'],
      });
    } catch (error) {
      if (error.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 점포입니다.');
      }
      throw new BadRequestException('점포 수정 실패');
    }
  }

  async remove(id: number, queryRunner: QueryRunner) {
    try {
      const store = await queryRunner.manager.findOne(Store, {
        where: { id },
      });

      if (!store) {
        throw new Error('not exist');
      }

      const deleted = await queryRunner.manager.delete(Store, { id });

      if (deleted.affected === 0) {
        throw new BadRequestException('점포 삭제 실패');
      }

      return { message: '점포 삭제 완료' };
    } catch (error) {
      if (error.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 점포입니다.');
      }
      throw new BadRequestException('점포 삭제 실패');
    }
  }

  async setWarehouse(Dto: SetStoreWarehouseDto, queryRunner: QueryRunner) {
    try {
      const store = await queryRunner.manager.exists(Store, {
        where: { id: Dto.storeId },
      });

      if (!store) {
        throw new NotFoundException('not exist');
      }

      const warehouse = await queryRunner.manager.exists(Warehouse, {
        where: { id: Dto.warehouseId },
      });

      if (!warehouse) {
        throw new NotFoundException('not exist');
      }

      await queryRunner.manager.update(
        Store,
        { id: Dto.storeId },
        { warehouse: { id: Dto.warehouseId } },
      );

      return await queryRunner.manager.findOne(Store, {
        where: { id: Dto.storeId },
      });
    } catch (e) {
      if (e.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 점포 또는 창고입니다.');
      }
      console.log(e);
      throw new BadRequestException('창고 설정 실패');
    }
  }
}
