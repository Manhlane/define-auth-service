import { MigrationInterface, QueryRunner } from 'typeorm';

export class DropVerificationTokens20260222093000
  implements MigrationInterface
{
  name = 'DropVerificationTokens20260222093000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "verification_tokens";`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`);
    await queryRunner.query(`
      CREATE TABLE "verification_tokens" (
        "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        "user_id" UUID NOT NULL,
        "token" VARCHAR NOT NULL UNIQUE,
        "type" VARCHAR NOT NULL,
        "expires_at" TIMESTAMP NOT NULL,
        "created_at" TIMESTAMP DEFAULT now(),
        CONSTRAINT "FK_tokens_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE
      );
    `);
  }
}
