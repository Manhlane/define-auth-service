import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { SessionModule } from 'src/session/session.module';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [UsersModule, SessionModule, JwtModule.register({
    secret: process.env.JWT_SECRET || 'default-secret',
    signOptions: { expiresIn: '1h' },
  }),],
  providers: [AuthService],
  controllers: [AuthController]
})
export class AuthModule { }
