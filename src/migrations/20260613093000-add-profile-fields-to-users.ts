import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddProfileFieldsToUsers20260613093000
  implements MigrationInterface
{
  name = 'AddProfileFieldsToUsers20260613093000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "users"
      ADD COLUMN IF NOT EXISTS "phone" character varying,
      ADD COLUMN IF NOT EXISTS "bankName" character varying,
      ADD COLUMN IF NOT EXISTS "accountNumber" character varying,
      ADD COLUMN IF NOT EXISTS "accountType" character varying,
      ADD COLUMN IF NOT EXISTS "avatarUrl" text
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "users"
      DROP COLUMN IF EXISTS "avatarUrl",
      DROP COLUMN IF EXISTS "accountType",
      DROP COLUMN IF EXISTS "accountNumber",
      DROP COLUMN IF EXISTS "bankName",
      DROP COLUMN IF EXISTS "phone"
    `);
  }
}
