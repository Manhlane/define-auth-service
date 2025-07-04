import { MigrationInterface, QueryRunner } from "typeorm";

export class RefreshTokenFix1751665952091 implements MigrationInterface {
    name = 'RefreshTokenFix1751665952091'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX "public"."IDX_e9f62f5dcb8a54b84234c9e7a0"`);
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "token"`);
        await queryRunner.query(`CREATE INDEX "IDX_3238ef96f18b355b671619111b" ON "sessions" ("id") `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX "public"."IDX_3238ef96f18b355b671619111b"`);
        await queryRunner.query(`ALTER TABLE "sessions" ADD "token" text NOT NULL`);
        await queryRunner.query(`CREATE INDEX "IDX_e9f62f5dcb8a54b84234c9e7a0" ON "sessions" ("token") `);
    }

}
