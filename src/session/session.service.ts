import { Injectable } from '@nestjs/common';
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
    rawToken: string,
    userAgent?: string,
    ipAddress?: string,
    location?: string,
    refreshToken?: string,
    expiresAt?: Date,
  ): Promise<Session> {
    const hashed = await bcrypt.hash(rawToken, 10);
    const hashedRefresh = refreshToken ? await bcrypt.hash(refreshToken, 10) : null;

    const session = this.sessionRepo.create({
      user,
      token: hashed,
      refreshToken: hashedRefresh,
      userAgent,
      ipAddress,
      location,
      expiresAt
    });
    return this.sessionRepo.save(session);
  }


  async validate(userId: string, incomingToken: string): Promise<boolean> {
    const sessions = await this.sessionRepo.find({
      where: { user: { id: userId }, isRevoked: false },
    });

    for (const session of sessions) {
      const isMatch = await bcrypt.compare(incomingToken, session.token);
      if (isMatch) return true;
    }

    return false;
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
