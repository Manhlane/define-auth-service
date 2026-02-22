import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreatePasswordResetTokens20260222104500
  implements MigrationInterface
{
  name = 'CreatePasswordResetTokens20260222104500';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE "password_reset_tokens" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "user_id" UUID NOT NULL,
        "token_hash" TEXT NOT NULL,
        "expires_at" TIMESTAMP NOT NULL,
        "used" BOOLEAN DEFAULT FALSE,
        "used_at" TIMESTAMP,
        "ip_address" character varying,
        "created_at" TIMESTAMP DEFAULT now(),
        CONSTRAINT "FK_password_reset_tokens_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE
      );
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "password_reset_tokens";`);
  }
}
