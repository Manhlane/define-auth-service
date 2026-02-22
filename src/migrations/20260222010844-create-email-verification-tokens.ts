import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateEmailVerificationTokens20260222010844
  implements MigrationInterface
{
  name = 'CreateEmailVerificationTokens20260222010844';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE "email_verification_tokens" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "user_id" UUID NOT NULL,
        "token_hash" TEXT NOT NULL,
        "expires_at" TIMESTAMP NOT NULL,
        "used" BOOLEAN DEFAULT FALSE,
        "created_at" TIMESTAMP DEFAULT now()
      );
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "email_verification_tokens";`);
  }
}
