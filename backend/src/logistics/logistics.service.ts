import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateLogisticDto } from './dto/create-logistic.dto';
import { UpdateLogisticDto } from './dto/update-logistic.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { QueryRunner, Repository } from 'typeorm';
import { Logistics } from './entities/logistics.entity';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';
import { CommonService } from 'src/common/common.service';
import { CreateWarehouseDto } from './dto/create-warehouse.dto';
import { Warehouse } from './entities/warehouse.entity';
import { UpdateWarehouseDto } from './dto/update-warehouse.dto';

@Injectable()
export class LogisticsService {
  constructor(
    @InjectRepository(Logistics)
    private logisticsRepository: Repository<Logistics>,
    @InjectRepository(Warehouse)
    private warehouseRepository: Repository<Warehouse>,
    private readonly commonService: CommonService,
  ) {}

  async create(
    Dto: CreateLogisticDto,
    queryRunner: QueryRunner,
  ): Promise<Logistics> {
    try {
      if (
        await queryRunner.manager.exists(Logistics, {
          where: { name: Dto.name },
        })
      ) {
        throw new BadRequestException('exist');
      }

      const newLogistics = queryRunner.manager.create(Logistics, Dto);
      return await queryRunner.manager.save(Logistics, newLogistics);
    } catch (error) {
      if (error.message === 'exist') {
        throw new BadRequestException('이미 존재하는 물류업체입니다.');
      }
      throw new BadRequestException('물류업체 생성에 실패했습니다.');
    }
  }

  async findAll(Dto: CursorPagenationDto): Promise<{
    results: Logistics[];
    nextCursor: string | null;
    count: number;
  }> {
    try {
      const qb = this.logisticsRepository.createQueryBuilder('logistics');

      // warehouse 관계를 함께 로드
      return await this.commonService.CursorPagenationParamsQb(
        qb,
        Dto,
        'warehouse',
      );
    } catch (error) {
      throw new BadRequestException(
        `물류업체 조회에 실패했습니다: ${error.message}`,
      );
    }
  }

  async findOne(id: number): Promise<Logistics> {
    try {
      const logistics = await this.logisticsRepository.findOne({
        where: { id },
        relations: ['warehouse'],
      });

      if (!logistics) {
        throw new NotFoundException('not exist');
      }

      return logistics;
    } catch (error) {
      if (error.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 물류업체입니다.');
      }

      throw new BadRequestException('물류업체 조회에 실패했습니다.');
    }
  }

  async update(
    id: number,
    Dto: UpdateLogisticDto,
    queryRunner: QueryRunner,
  ): Promise<Logistics> {
    try {
      if (!Dto) {
        throw new BadRequestException('no data');
      }
      if (
        !(await queryRunner.manager.exists(Logistics, {
          where: { id },
        }))
      ) {
        throw new NotFoundException('not exist');
      }
      await queryRunner.manager.update(Logistics, id, Dto);
      return await queryRunner.manager.findOne(Logistics, {
        where: { id },
        relations: ['warehouse'],
      });
    } catch (error) {
      if (error.message === 'no data') {
        throw new BadRequestException('수정할 데이터가 없습니다.');
      }
      if (error.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 물류업체입니다.');
      }
      throw new BadRequestException('물류업체 수정에 실패했습니다.');
    }
  }

  async remove(
    id: number,
    queryRunner: QueryRunner,
  ): Promise<{ message: string }> {
    try {
      const deleteEntity = await this.findOne(id);
      await queryRunner.manager.remove(deleteEntity);
      return { message: '물류업체가 삭제되었습니다.' };
    } catch {
      throw new BadRequestException('물류업체 삭제에 실패했습니다.');
    }
  }

  async createWarehouse(
    id: number,
    Dto: CreateWarehouseDto,
    queryRunner: QueryRunner,
  ): Promise<Warehouse> {
    try {
      if (!id) {
        throw new BadRequestException('no id');
      }

      if (
        !(await queryRunner.manager.exists(Logistics, {
          where: { id },
        }))
      ) {
        throw new NotFoundException('not exist');
      }

      if (
        await queryRunner.manager.exists(Warehouse, {
          where: { name: Dto.name },
        })
      ) {
        throw new BadRequestException('exist');
      }

      const newWarehouse = queryRunner.manager.create(Warehouse, {
        ...Dto,
        logistics: { id },
      });

      return await queryRunner.manager.save(Warehouse, newWarehouse);
    } catch (error) {
      if (error.message === 'no id') {
        throw new BadRequestException('물류업체 id가 없습니다.');
      }
      if (error.message === 'exist') {
        throw new BadRequestException('이미 존재하는 창고입니다.');
      }
      throw new BadRequestException('창고 생성에 실패했습니다.');
    }
  }

  async updateWarehouse(
    id: number,
    Dto: UpdateWarehouseDto,
    queryRunner: QueryRunner,
  ): Promise<Warehouse> {
    try {
      if (!id) {
        throw new BadRequestException('no id');
      }

      if (
        !(await queryRunner.manager.exists(Warehouse, {
          where: { id },
        }))
      ) {
        throw new NotFoundException('not exist');
      }

      await queryRunner.manager.update(Warehouse, id, Dto);
      return await queryRunner.manager.findOne(Warehouse, {
        where: { id },
      });
    } catch (error) {
      if (error.message === 'no id') {
        throw new BadRequestException('창고 id가 없습니다.');
      }
      if (error.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 창고입니다.');
      }
      throw new BadRequestException('창고 수정에 실패했습니다.');
    }
  }

  async removeWarehouse(
    id: number,
    queryRunner: QueryRunner,
  ): Promise<{ message: string }> {
    try {
      if (!id) {
        throw new BadRequestException('no id');
      }
      const deleteEntity = await this.warehouseRepository.findOne({
        where: { id },
      });
      if (!deleteEntity) {
        throw new NotFoundException('not exist');
      }
      await queryRunner.manager.remove(deleteEntity);
      return { message: '창고가 삭제되었습니다.' };
    } catch (error) {
      if (error.message === 'no id') {
        throw new BadRequestException('창고 id가 없습니다.');
      }
      if (error.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 창고입니다.');
      }
      throw new BadRequestException('창고 삭제에 실패했습니다.');
    }
  }
}
