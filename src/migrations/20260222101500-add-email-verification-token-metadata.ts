import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddEmailVerificationTokenMetadata20260222101500
  implements MigrationInterface
{
  name = 'AddEmailVerificationTokenMetadata20260222101500';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "email_verification_tokens" ADD "used_at" TIMESTAMP`,
    );
    await queryRunner.query(
      `ALTER TABLE "email_verification_tokens" ADD "ip_address" character varying`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "email_verification_tokens" DROP COLUMN "ip_address"`,
    );
    await queryRunner.query(
      `ALTER TABLE "email_verification_tokens" DROP COLUMN "used_at"`,
    );
  }
}
