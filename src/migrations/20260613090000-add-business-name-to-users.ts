import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddBusinessNameToUsers20260613090000
  implements MigrationInterface
{
  name = 'AddBusinessNameToUsers20260613090000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "users"
      ADD COLUMN IF NOT EXISTS "businessName" character varying
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "users"
      DROP COLUMN IF EXISTS "businessName"
    `);
  }
}
