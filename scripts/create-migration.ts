import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

const name = process.argv[2];

if (!name) {
  console.error('❌ Please provide a name for the migration.');
  console.error('Usage: npm run migration:new init-auth-schema');
  process.exit(1);
}

const timestamp = Date.now();
const classNameBase = name
  .split('-')
  .map(part => part.charAt(0).toUpperCase() + part.slice(1))
  .join('');
const className = `${classNameBase}${timestamp}`;
const fileName = `${timestamp}-${name}.ts`;
const migrationsDir = join(__dirname, '../src/migrations');
const filePath = join(migrationsDir, fileName);

if (!existsSync(migrationsDir)) {
  mkdirSync(migrationsDir, { recursive: true });
}

const template = `import { MigrationInterface, QueryRunner } from 'typeorm';

export class ${className} implements MigrationInterface {
  name = '${className}'

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(\`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";\`);

    await queryRunner.query(\`
      CREATE TABLE "users" (
        "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        "email" VARCHAR NOT NULL UNIQUE,
        "name" VARCHAR,
        "password" VARCHAR NOT NULL,
        "role" VARCHAR DEFAULT 'user',
        "is_email_verified" BOOLEAN DEFAULT FALSE,
        "created_at" TIMESTAMP DEFAULT now(),
        "updated_at" TIMESTAMP DEFAULT now()
      );
    \`);

    await queryRunner.query(\`
      CREATE TABLE "sessions" (
        "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        "user_id" UUID NOT NULL,
        "token" VARCHAR NOT NULL UNIQUE,
        "expires_at" TIMESTAMP NOT NULL,
        "created_at" TIMESTAMP DEFAULT now(),
        CONSTRAINT "FK_sessions_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE
      );
    \`);

  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(\`DROP TABLE IF EXISTS "sessions";\`);
    await queryRunner.query(\`DROP TABLE IF EXISTS "users";\`);
  }
}
`;

writeFileSync(filePath, template);
console.log('✅ Migration with full auth schema created:', filePath);
