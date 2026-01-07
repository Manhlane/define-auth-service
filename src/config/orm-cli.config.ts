import { DataSource } from 'typeorm';
import { config } from 'dotenv';
import { join } from 'path';

config(); // Loads .env

const entitiesGlob = join(__dirname, '..', '**', '*.entity.{ts,js}');
const migrationsGlob = join(__dirname, '..', 'migrations', '*{.ts,.js}');

const AppDataSource = new DataSource({
  type: 'postgres',
  url: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
  synchronize: false,
  entities: [entitiesGlob],
  migrations: [migrationsGlob],
});

export default AppDataSource;
