import { MigrationInterface, QueryRunner } from "typeorm";

export class UpdateUserAndSessionEntities1751278248786 implements MigrationInterface {
    name = 'UpdateUserAndSessionEntities1751278248786'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "sessions" DROP CONSTRAINT "FK_sessions_user"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "user_id"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "expires_at"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "created_at"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "role"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "is_email_verified"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "created_at"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "updated_at"`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "refreshToken" text`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "expiresAt" TIMESTAMP`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "isRevoked" boolean NOT NULL DEFAULT false`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "userAgent" character varying`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "ipAddress" character varying`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "location" character varying`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "createdAt" TIMESTAMP NOT NULL DEFAULT now()`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "userId" uuid`);
        await queryRunner.query(`ALTER TABLE "users" ADD "createdAt" TIMESTAMP NOT NULL DEFAULT now()`);
        await queryRunner.query(`ALTER TABLE "users" ADD "updatedAt" TIMESTAMP NOT NULL DEFAULT now()`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP CONSTRAINT "sessions_token_key"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "token"`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "token" text NOT NULL`);
        await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "name" SET NOT NULL`);
        await queryRunner.query(`CREATE INDEX "IDX_e9f62f5dcb8a54b84234c9e7a0" ON "sessions" ("token") `);
        await queryRunner.query(`ALTER TABLE "sessions" ADD CONSTRAINT "FK_57de40bc620f456c7311aa3a1e6" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "sessions" DROP CONSTRAINT "FK_57de40bc620f456c7311aa3a1e6"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_e9f62f5dcb8a54b84234c9e7a0"`);
        await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "name" DROP NOT NULL`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "token"`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "token" character varying NOT NULL`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD CONSTRAINT "sessions_token_key" UNIQUE ("token")`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "updatedAt"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "createdAt"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "userId"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "createdAt"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "location"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "ipAddress"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "userAgent"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "isRevoked"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "expiresAt"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "refreshToken"`);
        await queryRunner.query(`ALTER TABLE "users" ADD "updated_at" TIMESTAMP DEFAULT now()`);
        await queryRunner.query(`ALTER TABLE "users" ADD "created_at" TIMESTAMP DEFAULT now()`);
        await queryRunner.query(`ALTER TABLE "users" ADD "is_email_verified" boolean DEFAULT false`);
        await queryRunner.query(`ALTER TABLE "users" ADD "role" character varying DEFAULT 'user'`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "created_at" TIMESTAMP DEFAULT now()`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "expires_at" TIMESTAMP NOT NULL`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "user_id" uuid NOT NULL`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD CONSTRAINT "FK_sessions_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

}
