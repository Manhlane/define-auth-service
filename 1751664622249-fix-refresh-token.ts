import { MigrationInterface, QueryRunner } from "typeorm";

export class FixRefreshToken1751664622249 implements MigrationInterface {
    name = 'FixRefreshToken1751664622249'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE INDEX "IDX_3238ef96f18b355b671619111b" ON "sessions" ("id") `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX "public"."IDX_3238ef96f18b355b671619111b"`);
    }

}
