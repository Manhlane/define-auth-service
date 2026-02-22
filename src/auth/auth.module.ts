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
import { EmailVerificationToken } from './entities/email-verification-token.entity';
import { PasswordResetToken } from './entities/password-reset-token.entity';
import { GoogleStrategy } from './strategies/google.strategy';
import { NotificationsClient } from 'src/notifications/notifications.client';

@Module({
  imports: [
    ConfigModule,
    UsersModule,
    SessionModule,
    TypeOrmModule.forFeature([
      Session,
      EmailVerificationToken,
      PasswordResetToken,
    ]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_ACCESS_SECRET'),
        signOptions: { expiresIn: '1h' },
      }),
    }),
  ],
  providers: [AuthService, JwtStrategy, GoogleStrategy, NotificationsClient],
  controllers: [AuthController],
})
export class AuthModule {}
