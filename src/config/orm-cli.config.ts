import { DataSource } from 'typeorm';
import { config } from 'dotenv';
import { join } from 'path';

config(); // Loads .env

const AppDataSource = new DataSource({
  type: 'postgres',
  url: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
  synchronize: false,
  entities: ['src/**/*.entity.{ts,js}'],
  migrations: ['src/migrations/*{.ts,.js}'],
});

export default AppDataSource;