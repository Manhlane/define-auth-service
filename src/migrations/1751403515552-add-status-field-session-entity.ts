import { MigrationInterface, QueryRunner } from "typeorm";

export class AddStatusFieldSessionEntity1751403515552 implements MigrationInterface {
    name = 'AddStatusFieldSessionEntity1751403515552'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "sessions" ADD "status" character varying NOT NULL DEFAULT 'active'`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "sessions" DROP COLUMN "status"`);
    }

}
