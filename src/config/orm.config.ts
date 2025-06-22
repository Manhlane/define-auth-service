import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleAsyncOptions } from '@nestjs/typeorm';
import { DataSourceOptions } from 'typeorm';

export const typeOrmConfig: TypeOrmModuleAsyncOptions = {
  useFactory: async (configService: ConfigService): Promise<DataSourceOptions> => {
    const dbUrl = configService.get<string>('DATABASE_URL');

    console.log('[TypeORM] DATABASE_URL:', dbUrl);

    return {
      type: 'postgres',
      url: dbUrl,
      ssl: {
        rejectUnauthorized: false,
      },
      synchronize: false,
      entities: [__dirname + '/../**/*.entity{.ts,.js}'],
      migrations: [__dirname + '/../migrations/*{.ts,.js}'],
    };
  },
  inject: [ConfigService],
};
