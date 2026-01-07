import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdatedUserEntity1751317201246 implements MigrationInterface {
  name = 'UpdatedUserEntity1751317201246';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "users" ADD "isVerified" boolean NOT NULL DEFAULT false`,
    );
    await queryRunner.query(
      `ALTER TABLE "users" ADD "roles" text NOT NULL DEFAULT 'user'`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "roles"`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "isVerified"`);
  }
}
