// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { SessionModule } from 'src/session/session.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Session } from 'src/session/entities/session.entity';

@Module({
  imports: [
    UsersModule,
    SessionModule,
    TypeOrmModule.forFeature([Session]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_ACCESS_SECRET'),
        signOptions: { expiresIn: '1h' },
      }),
    }),
  ],
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
