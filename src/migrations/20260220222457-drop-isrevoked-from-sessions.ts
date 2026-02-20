import { MigrationInterface, QueryRunner } from 'typeorm';

export class DropIsrevokedFromSessions20260220222457
  implements MigrationInterface
{
  name = 'DropIsrevokedFromSessions20260220222457';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "sessions" DROP COLUMN "isRevoked"`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "sessions" ADD "isRevoked" boolean NOT NULL DEFAULT false`,
    );
  }
}
