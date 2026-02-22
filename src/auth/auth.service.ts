import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from 'src/users/users.service';
import { SessionService } from '../session/session.service';
import { LoginDto } from './dto/login.dto';
import { User } from 'src/users/entities/user.entity';
import { RegisterDto } from './dto/register.dto';
import { createHash, randomUUID } from 'crypto';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Session } from '../session/entities/session.entity';
import { NotificationsClient } from 'src/notifications/notifications.client';
import { EmailVerificationToken } from './entities/email-verification-token.entity';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly sessionService: SessionService,
    private readonly configService: ConfigService,
    @InjectRepository(Session)
    private readonly sessionRepo: Repository<Session>,
    @InjectRepository(EmailVerificationToken)
    private readonly emailVerificationTokenRepo: Repository<EmailVerificationToken>,
    private readonly notificationsClient: NotificationsClient,
  ) {}

  private get accessTokenSecret(): string | undefined {
    return this.configService.get<string>('JWT_ACCESS_SECRET');
  }

  private get accessTokenExpiry(): string {
    return this.configService.get<string>('ACCESS_TOKEN_EXPIRY') ?? '15m';
  }

  private get refreshTokenExpiryMs(): number {
    return parseInt(
      this.configService.get<string>('REFRESH_TOKEN_EXPIRY_MS') ?? '86400000',
      10,
    );
  }

  private get passwordResetSecret(): string | undefined {
    return (
      this.configService.get<string>('JWT_PASSWORD_RESET_SECRET') ??
      this.accessTokenSecret
    );
  }

  private get passwordResetExpiry(): string {
    return (
      this.configService.get<string>('PASSWORD_RESET_TOKEN_EXPIRY') ?? '15m'
    );
  }

  private get emailVerificationSecret(): string | undefined {
    return (
      this.configService.get<string>('JWT_EMAIL_VERIFICATION_SECRET') ??
      this.accessTokenSecret
    );
  }

  private get emailVerificationExpiry(): string {
    return (
      this.configService.get<string>('EMAIL_VERIFICATION_TOKEN_EXPIRY') ?? '1d'
    );
  }

  private get appBaseUrl(): string {
    return (
      this.configService.get<string>('APP_BASE_URL') ??
      'http://34.251.72.37:3002'
    );
  }

  private buildJwtOptions(secret: string | undefined, expiresIn: string) {
    return secret ? { secret, expiresIn } : { expiresIn };
  }

  private parseDurationToMs(value: string): number {
    const trimmed = value.trim();
    const match = /^(\d+)([smhd])$/.exec(trimmed);
    if (!match) {
      const asNumber = Number(trimmed);
      if (!Number.isNaN(asNumber)) {
        return asNumber;
      }
      return 24 * 60 * 60 * 1000;
    }

    const amount = Number(match[1]);
    const unit = match[2];
    switch (unit) {
      case 's':
        return amount * 1000;
      case 'm':
        return amount * 60 * 1000;
      case 'h':
        return amount * 60 * 60 * 1000;
      case 'd':
        return amount * 24 * 60 * 60 * 1000;
      default:
        return 24 * 60 * 60 * 1000;
    }
  }

  private getVerificationTokenExpiry(token: string): Date {
    const decoded = this.jwtService.decode(token) as { exp?: number } | null;
    if (decoded?.exp) {
      return new Date(decoded.exp * 1000);
    }

    const fallbackMs = this.parseDurationToMs(this.emailVerificationExpiry);
    return new Date(Date.now() + fallbackMs);
  }

  private hashVerificationToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private async markEmailVerificationTokenUsed(token: string): Promise<void> {
    const tokenHash = this.hashVerificationToken(token);
    await this.emailVerificationTokenRepo.update(
      { tokenHash, used: false },
      { used: true },
    );
  }

  private async storeEmailVerificationToken(
    userId: string,
    token: string,
  ): Promise<void> {
    const tokenHash = this.hashVerificationToken(token);
    const expiresAt = this.getVerificationTokenExpiry(token);

    await this.emailVerificationTokenRepo.save({
      userId,
      tokenHash,
      expiresAt,
      used: false,
    });
  }

  private sanitizeUser(user: User) {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      isVerified: user.isVerified,
      roles: user.roles,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  private async generateEmailVerificationToken(user: User): Promise<string> {
    const payload = {
      sub: user.id,
      email: user.email,
      type: 'email-verification',
    };
    return this.jwtService.signAsync(
      payload,
      this.buildJwtOptions(
        this.emailVerificationSecret,
        this.emailVerificationExpiry,
      ),
    );
  }

  private async generatePasswordResetToken(user: User): Promise<string> {
    const payload = { sub: user.id, email: user.email, type: 'password-reset' };
    return this.jwtService.signAsync(
      payload,
      this.buildJwtOptions(this.passwordResetSecret, this.passwordResetExpiry),
    );
  }

  async refreshToken(
    refreshToken: string,
    userId: string,
  ): Promise<{ accessToken: string }> {
    const sessions = await this.sessionRepo.find({
      where: {
        status: 'active',
        user: { id: userId },
      },
      relations: ['user'],
    });

    let matchedSession: Session | null = null;

    for (const session of sessions) {
      const isMatch = await bcrypt.compare(refreshToken, session.refreshToken);
      if (isMatch) {
        matchedSession = session;
        break;
      }
    }

    if (!matchedSession) {
      throw new UnauthorizedException('Refresh token invalid or expired');
    }

    if (matchedSession.expiresAt && matchedSession.expiresAt < new Date()) {
      await this.sessionService.revokeSessionById(matchedSession.id);
      throw new UnauthorizedException('Refresh token invalid or expired');
    }

    const user = matchedSession.user;

    const payload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
    };

    const newAccessToken = await this.jwtService.signAsync(
      payload,
      this.buildJwtOptions(this.accessTokenSecret, this.accessTokenExpiry),
    );

    return { accessToken: newAccessToken };
  }

  async logout(
    userId: string,
    sessionId: string,
    ip?: string,
    userAgent?: string,
  ) {
    const session = await this.sessionRepo.findOne({
      where: { id: sessionId, user: { id: userId } },
    });

    const sessionFound = Boolean(session);
    this.logger.log({
      event: 'USER_LOGOUT',
      userId,
      sessionId,
      ip,
      userAgent,
      sessionFound,
    });

    if (sessionFound) {
      await this.sessionService.revokeSingleSession(sessionId);
    }

    return { message: 'Logged out successfully' };
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.usersService.findByEmail(email);
  }

  async register(dto: RegisterDto) {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const existingUser = await this.usersService.findByEmail(normalizedEmail);
    if (existingUser) throw new ConflictException('Email already in use');

    const hashedPassword = await bcrypt.hash(dto.password, 10);
    const user = await this.usersService.create({
      email: normalizedEmail,
      name: dto.name,
      password: hashedPassword,
    });

    const verificationToken = await this.generateEmailVerificationToken(user);
    const verificationUrl = this.buildVerificationUrl(verificationToken);

    try {
      await this.notificationsClient.sendWelcomeEmail({
        email: user.email,
        name: user.name,
        verificationUrl,
      });
    } catch (error) {
      this.logger.warn(
        `Failed to enqueue welcome email for ${user.email}: ${error}`,
      );
    }

    try {
      await this.storeEmailVerificationToken(user.id, verificationToken);
    } catch (error) {
      this.logger.warn(
        `Failed to store email verification token for ${user.email}: ${error}`,
      );
    }

    return {
      ...this.sanitizeUser(user),
      verificationToken,
    };
  }

  async login(
    loginDto: LoginDto,
    userAgent?: string,
    ipAddress?: string,
    location?: string,
  ) {
    const normalizedEmail = loginDto.email.trim().toLowerCase();
    const user = await this.usersService.findByEmail(normalizedEmail);

    if (!user) {
      throw new NotFoundException(
        `No account found for email: ${loginDto.email}`,
      );
    }

    if (!user.password) {
      throw new UnauthorizedException(
        'Account is registered via a social login provider',
      );
    }

    const isPasswordValid = await bcrypt.compare(
      loginDto.password,
      user.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Incorrect password');
    }

    const payload = { sub: user.id, email: user.email, roles: user.roles };
    const accessToken = await this.jwtService.signAsync(
      payload,
      this.buildJwtOptions(this.accessTokenSecret, this.accessTokenExpiry),
    );

    const refreshToken = randomUUID();
    const expiresAt = new Date(Date.now() + this.refreshTokenExpiryMs);

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
      isVerified: user.isVerified,
    };
  }

  async loginWithGoogle(
    googleUser: any,
    userAgent?: string,
    ipAddress?: string,
    location?: string,
  ) {
    const normalizedEmail = googleUser.email.toLowerCase();
    let user = await this.usersService.findByEmail(normalizedEmail);
    let isFirstSocialLogin = false;

    if (!user) {
      const generatedPassword = await bcrypt.hash(randomUUID(), 10);
      const name =
        `${googleUser.firstName ?? ''} ${googleUser.lastName ?? ''}`.trim();
      user = await this.usersService.create({
        email: normalizedEmail,
        name: name || googleUser.email,
        password: generatedPassword,
        isVerified: true,
        roles: googleUser.roles ?? ['user'],
      });
      isFirstSocialLogin = true;
    }

    const payload = { sub: user.id, email: user.email, roles: user.roles };
    const userProfile = this.sanitizeUser(user);

    const accessToken = await this.jwtService.signAsync(
      payload,
      this.buildJwtOptions(this.accessTokenSecret, this.accessTokenExpiry),
    );

    const refreshToken = randomUUID();
    const expiresAt = new Date(Date.now() + this.refreshTokenExpiryMs);

    await this.sessionService.create(
      user,
      refreshToken,
      userAgent,
      ipAddress,
      location,
      expiresAt,
    );

    if (isFirstSocialLogin) {
      this.notificationsClient
        .sendWelcomeEmail({
          email: user.email,
          name: user.name,
        })
        .catch((error) =>
          this.logger.warn(
            `Failed to enqueue social welcome email for ${user.email}: ${error}`,
          ),
        );
    }

    return {
      message: 'Google login successful',
      userId: user.id,
      accessToken,
      refreshToken,
      user: userProfile,
    };
  }

  async requestPasswordReset(email: string) {
    const normalizedEmail = email.trim().toLowerCase();
    const user = await this.usersService.findByEmail(normalizedEmail);

    if (!user) {
      return {
        message:
          'If an account exists for this email, reset instructions have been sent.',
      };
    }

    const resetToken = await this.generatePasswordResetToken(user);

    return {
      message: 'Password reset instructions generated successfully.',
      resetToken,
      expiresIn: this.passwordResetExpiry,
    };
  }

  async resendVerification(email: string) {
    const normalizedEmail = email.trim().toLowerCase();
    const user = await this.usersService.findByEmail(normalizedEmail);

    if (!user) {
      return {
        message:
          'If an account exists for this email, verification details have been sent.',
      };
    }

    const verificationToken = await this.generateEmailVerificationToken(user);

    return {
      message: user.isVerified
        ? 'Account already verified. Verification link regenerated.'
        : 'Verification link generated successfully.',
      verificationToken,
    };
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.password) {
      throw new UnauthorizedException(
        'Password changes are not available for this account',
      );
    }

    const isCurrentValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    if (currentPassword === newPassword) {
      throw new BadRequestException(
        'New password must be different from the current password',
      );
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.usersService.updateUser(user.id, { password: hashedPassword });
    await this.sessionService.revoke(user.id);
  }

  async verifyEmail(token: string): Promise<void> {
    let payload: any;

    try {
      const secret = this.emailVerificationSecret;
      payload = await this.jwtService.verifyAsync(
        token,
        secret ? { secret } : undefined,
      );
    } catch (error) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    if (payload.type !== 'email-verification' || !payload.sub) {
      throw new BadRequestException('Invalid email verification token');
    }

    const user = await this.usersService.findById(payload.sub);
    if (!user) {
      throw new NotFoundException('User account not found');
    }

    if (!user.isVerified) {
      await this.usersService.updateUser(user.id, { isVerified: true });
    }

    await this.markEmailVerificationTokenUsed(token);
  }

  async getProfile(userId: string) {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.sanitizeUser(user);
  }

  async getUserRoles(userId: string) {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    return { roles: user.roles };
  }

  private buildVerificationUrl(token: string): string {
    try {
      const url = new URL('/verify-email', this.appBaseUrl);
      url.searchParams.set('token', token);
      return url.toString();
    } catch (error) {
      this.logger.warn(
        `Failed to build verification URL, falling back to token only: ${error}`,
      );
      return token;
    }
  }
}
