import { BadRequestException, Injectable } from '@nestjs/common';
import { SelectQueryBuilder } from 'typeorm';
import { CursorPagenationDto } from './dto/cursor-pagenation.dto';

@Injectable()
export class CommonService {
  constructor() {}

  /**
   * 범용 커서 기반 페이지네이션 메소드
   * @param qb 쿼리빌더
   * @param CPDto 커서 페이지네이션 DTO
   * @param relations 로드할 관계 목록 (선택적)
   */
  async CursorPagenationParamsQb<T>(
    qb: SelectQueryBuilder<T>,
    CPDto: CursorPagenationDto,
    relations?: string | string[],
  ) {
    try {
      const { cursor, take } = CPDto;
      let { order } = CPDto;

      /** order가 유효한 배열인지 확인 */
      if (!Array.isArray(order) || order.length === 0) {
        order = ['id_DESC']; // 기본값 설정
      }

      /** 관계 데이터 로드 설정 */
      if (relations) {
        const relationArray = Array.isArray(relations)
          ? relations
          : [relations];
        relationArray.forEach((relation) => {
          qb.leftJoinAndSelect(`${qb.alias}.${relation}`, relation);
        });
      }

      /** 커서 기반 쿼리 조건 설정 */
      if (cursor) {
        try {
          const decodedCursor = Buffer.from(cursor, 'base64').toString('utf-8');
          const cursorObj = JSON.parse(decodedCursor);

          /** 커서에서 가져온 order가 유효한지 확인 */
          if (Array.isArray(cursorObj.order) && cursorObj.order.length > 0) {
            order = cursorObj.order;
          }

          const { values } = cursorObj;

          if (!values || typeof values !== 'object') {
            throw new Error('커서에 values 객체가 없거나 유효하지 않습니다');
          }

          const columns = Object.keys(values);
          if (columns.length === 0) {
            throw new Error('커서에 컬럼 정보가 없습니다');
          }

          /** order 정보를 기반으로 내림차순(DESC) 여부 확인 */
          const isDesc = order.some((o) => o.endsWith('DESC'));
          const comparisonOperator = isDesc ? '<' : '>';

          /** 단일 컬럼 */
          if (columns.length === 1) {
            const column = columns[0];
            qb.where(`${qb.alias}.${column} ${comparisonOperator} :${column}`, {
              [column]: values[column],
            });
          } else {
            /** 다중 컬럼 */
            const conditions = [];
            const params = {};

            /** 주 비교 조건 (첫 번째 컬럼) */
            const firstColumn = columns[0];
            conditions.push(
              `${qb.alias}.${firstColumn} ${comparisonOperator} :${firstColumn}`,
            );
            params[firstColumn] = values[firstColumn];

            /** 첫 번째 컬럼이 같을 경우 다음 컬럼으로 비교 */
            for (let i = 1; i < columns.length; i++) {
              const prevColumn = columns[i - 1];
              const currentColumn = columns[i];

              conditions.push(
                `(${qb.alias}.${prevColumn} = :${prevColumn} AND ${qb.alias}.${currentColumn} ${comparisonOperator} :${currentColumn})`,
              );
              params[currentColumn] = values[currentColumn];
            }

            qb.where(conditions.join(' OR '), params);
          }
        } catch (error) {
          throw new BadRequestException(`잘못된 커서 형식: ${error.message}`);
        }
      }

      // 정렬 설정
      for (let i = 0; i < order.length; i++) {
        const parts = order[i].split('_');

        if (parts.length !== 2) {
          throw new BadRequestException(`잘못된 정렬 형식: ${order[i]}`);
        }

        const column = parts[0];
        const direction = parts[1];

        if (direction !== 'ASC' && direction !== 'DESC') {
          throw new BadRequestException('옳지 않은 정렬요청');
        }

        if (i === 0) {
          qb.orderBy(`${qb.alias}.${column}`, direction as 'ASC' | 'DESC');
        } else {
          qb.addOrderBy(`${qb.alias}.${column}`, direction as 'ASC' | 'DESC');
        }
      }

      /** 페이지 크기 설정 */
      const pageSize = take || 10;
      qb.take(pageSize);

      /** 쿼리 실행 및 결과 반환 */
      const results = await qb.getMany();
      const count = results.length;
      const nextCursor =
        results.length > 0 ? this.generateNextCursor(results, order) : null;

      return { results, nextCursor, count };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new BadRequestException(
        `페이지네이션 처리 중 오류: ${error.message}`,
      );
    }
  }

  generateNextCursor<T>(results: T[], order: string[]): string | null {
    if (results.length === 0) {
      return null;
    }

    const lastItem = results[results.length - 1];
    const values = {};

    order.forEach((columnOrder) => {
      const [column] = columnOrder.split('_');
      values[column] = lastItem[column];
    });

    const cursorObj = { values, order };
    const nextCursor = Buffer.from(JSON.stringify(cursorObj)).toString(
      'base64',
    );

    return nextCursor;
  }
}
