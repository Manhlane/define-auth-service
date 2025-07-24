import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Session } from './entities/session.entity';
import { User } from 'src/users/entities/user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class SessionService {
  constructor(
    @InjectRepository(Session)
    private readonly sessionRepo: Repository<Session>,
  ) { }

  async create(
    user: User,
    refreshToken: string,
    userAgent?: string,
    ipAddress?: string,
    location?: string,
    expiresAt?: Date,
  ): Promise<Session> {
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    const session = this.sessionRepo.create({
      user,
      refreshToken: hashedToken,
      userAgent,
      ipAddress,
      location,
      expiresAt,
    });
    return this.sessionRepo.save(session);
  }

  async revokeSessionById(sessionId: string): Promise<void> {
    await this.sessionRepo.update({ id: sessionId }, { status: 'active', expiresAt: new Date() });
  }


  async revoke(userId: string): Promise<void> {
    await this.sessionRepo.update({ user: { id: userId } }, { status: 'revoked' });
  }

  async revokeSingleSession(sessionId: string): Promise<void> {
    await this.sessionRepo.update({ id: sessionId }, { status: 'revoked' });
  }

  async getActiveSessions(userId: string): Promise<Session[]> {
    return this.sessionRepo.find({
      where: { user: { id: userId }, status: "active" },
      order: { createdAt: 'DESC' },
    });
  }
}

