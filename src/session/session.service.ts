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
    console.log("Refresh Token: " + refreshToken)
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    console.log("Hashed Token: " + hashedToken);
    const session = this.sessionRepo.create({
      user,
      refreshToken: hashedToken,
      userAgent,
      ipAddress,
      location,
      expiresAt,
    });

    console.log("Session:" + session);
    console.log("Session User:" + session.user.name);
    console.log("Session refreshToken:" + session.refreshToken);
    console.log("Session expiresAt:" + session.expiresAt);
    
    return this.sessionRepo.save(session);
  }

  async revokeSessionById(sessionId: string): Promise<void> {
    await this.sessionRepo.update({ id: sessionId }, { isRevoked: true, expiresAt: new Date() });
  }


  async revoke(userId: string): Promise<void> {
    await this.sessionRepo.update({ user: { id: userId } }, { isRevoked: true });
  }

  async revokeSingleSession(sessionId: string): Promise<void> {
    await this.sessionRepo.update({ id: sessionId }, { isRevoked: true });
  }

  async getActiveSessions(userId: string): Promise<Session[]> {
    return this.sessionRepo.find({
      where: { user: { id: userId }, isRevoked: false },
      order: { createdAt: 'DESC' },
    });
  }
}

