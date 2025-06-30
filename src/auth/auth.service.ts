import { ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from 'src/users/users.service';
import { SessionService } from '../session/session.service';
import { LoginDto } from './dto/login.dto';
import { User } from 'src/users/entities/user.entity';
import { RegisterDto } from './dto/register.dto';
import { randomUUID } from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly sessionService: SessionService,
  ) {}

  async refreshAccessToken(refresh_token: string) {
    try {
      const payload = this.jwtService.verify(refresh_token, {
        secret: process.env.REFRESH_TOKEN_SECRET,
      });

      const user = await this.usersService.findById(payload.sub);
      if (!user) throw new UnauthorizedException('User not found');

      const valid = await this.sessionService.validate(user.id, refresh_token);
      if (!valid) throw new UnauthorizedException('Invalid or expired session');

      const newAccessToken = this.jwtService.sign(
        { sub: user.id, email: user.email },
        { expiresIn: '15m' },
      );

      return { access_token: newAccessToken };
    } catch (e) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async logout(userId: string) {
    await this.sessionService.revoke(userId);
    return { message: 'Logged out successfully' };
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.usersService.findByEmail(email);
  }

  async register(dto: RegisterDto) {
    const existingUser = await this.usersService.findByEmail(dto.email);
    if (existingUser) throw new ConflictException('Email already in use');
  
    const hashedPassword = await bcrypt.hash(dto.password, 10);
    const user = await this.usersService.create({
      email: dto.email,
      name: dto.name,
      password: hashedPassword,
    });
  
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      isVerified: user.isVerified,
      roles: user.roles,
    };
  }

  async login(loginDto: LoginDto, userAgent?: string, ipAddress?: string, location?: string) {
    const { email, password } = loginDto;
  
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new NotFoundException(`No account found for email: ${email}`);
    }
  
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Incorrect password');
    }
  
    const payload = { sub: user.id, email: user.email };
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
    });
  
    const refreshToken = randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days from now
  
    await this.sessionService.create(
      user,
      refreshToken,
      userAgent,
      ipAddress,
      location,
      undefined,
      expiresAt,
    );
  
    return {
      message: 'Login successful',
      userId: user.id,
      accessToken,
      refreshToken,
    };
  }
  
}
