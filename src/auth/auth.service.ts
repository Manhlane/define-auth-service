import { ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from 'src/users/users.service';
import { SessionService } from '../session/session.service';
import { LoginDto } from './dto/login.dto';
import { User } from 'src/users/entities/user.entity';
import { RegisterDto } from './dto/register.dto';
import { randomUUID } from 'crypto';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Session } from '../session/entities/session.entity';


@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly sessionService: SessionService,
    private readonly configService: ConfigService,
    @InjectRepository(Session)
    private readonly sessionRepo: Repository<Session>,
  ) { }

  async refreshToken(refreshToken: string, userId: string): Promise<{ accessToken: string }> {
    const sessions = await this.sessionRepo.find({
      where: {
        isRevoked: false,
        user: { id: userId },
      },
      relations: ['user'],
    });
  
    console.log(sessions[0].user.email)
    let matchedSession: Session | null = null;
  
    for (const session of sessions) {
      console.log(sessions[0].refreshToken)

      const isMatch = await bcrypt.compare(refreshToken, session.refreshToken);
      if (isMatch) {
        matchedSession = session;
        break;
      }
    }
  
    if (!matchedSession || matchedSession.expiresAt < new Date()) {
      throw new UnauthorizedException('Refresh token invalid or expired');
    }
  
    const user = matchedSession.user;
  
    const payload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
    };
  
    const newAccessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
      secret: this.configService.get('JWT_ACCESS_SECRET'),
    });
  
    return { accessToken: newAccessToken };
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
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await this.sessionService.create(
      user,
      refreshToken,
      userAgent,
      ipAddress,
      location,
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
