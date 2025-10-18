import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { SessionService } from 'src/session/session.service';
import { ConfigService } from '@nestjs/config';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Session } from 'src/session/entities/session.entity';
import {
  BadRequestException,
  ConflictException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';

describe('AuthService', () => {
  let service: AuthService;
  let usersService: jest.Mocked<{
    findByEmail: jest.Mock;
    findById: jest.Mock;
    create: jest.Mock;
    updateUser: jest.Mock;
  }>;
  let jwtService: jest.Mocked<{ signAsync: jest.Mock; verifyAsync: jest.Mock }>;
  let sessionService: jest.Mocked<{
    create: jest.Mock;
    revoke: jest.Mock;
    revokeSessionById: jest.Mock;
  }>;
  let configService: jest.Mocked<{ get: jest.Mock }>;
  let sessionRepo: jest.Mocked<{ find: jest.Mock }>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: {
            findByEmail: jest.fn(),
            findById: jest.fn(),
            create: jest.fn(),
            updateUser: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            signAsync: jest.fn(),
            verifyAsync: jest.fn(),
          },
        },
        {
          provide: SessionService,
          useValue: {
            create: jest.fn(),
            revoke: jest.fn(),
            revokeSessionById: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(Session),
          useValue: {
            find: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    usersService = module.get(UsersService);
    jwtService = module.get(JwtService);
    sessionService = module.get(SessionService);
    configService = module.get(ConfigService);
    sessionRepo = module.get(getRepositoryToken(Session));

    configService.get.mockImplementation((key: string) => {
      switch (key) {
        case 'JWT_ACCESS_SECRET':
          return 'access-secret';
        case 'ACCESS_TOKEN_EXPIRY':
          return '15m';
        case 'REFRESH_TOKEN_EXPIRY_MS':
          return '86400000';
        case 'JWT_PASSWORD_RESET_SECRET':
          return 'reset-secret';
        case 'PASSWORD_RESET_TOKEN_EXPIRY':
          return '10m';
        case 'JWT_EMAIL_VERIFICATION_SECRET':
          return 'verify-secret';
        case 'EMAIL_VERIFICATION_TOKEN_EXPIRY':
          return '1d';
        default:
          return undefined;
      }
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  const mockUser = (overrides: Partial<any> = {}) => ({
    id: 'user-id',
    email: 'user@example.com',
    name: 'Test User',
    password: 'hashed-password',
    roles: ['user'],
    isVerified: false,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    it('should lower-case email, hash password, and return verification token', async () => {
      usersService.findByEmail.mockResolvedValue(null);
      const user = mockUser();
      usersService.create.mockResolvedValue(user);
      jwtService.signAsync.mockResolvedValueOnce('verification-token');

      const result = await service.register({
        email: 'User@Example.com',
        name: 'Test User',
        password: 'PlainPassword1!',
      });

      expect(usersService.findByEmail).toHaveBeenCalledWith('user@example.com');
      expect(usersService.create).toHaveBeenCalledTimes(1);
      const createPayload = usersService.create.mock.calls[0][0];
      expect(createPayload.email).toBe('user@example.com');
      expect(createPayload.password).not.toBe('PlainPassword1!');
      expect(result).toMatchObject({
        id: user.id,
        email: user.email,
        name: user.name,
        verificationToken: 'verification-token',
      });
      expect(result).not.toHaveProperty('password');
    });

    it('should throw when email already exists', async () => {
      usersService.findByEmail.mockResolvedValue(mockUser());

      await expect(
        service.register({ email: 'existing@example.com', name: 'Bob', password: 'test' }),
      ).rejects.toBeInstanceOf(ConflictException);
    });
  });

  describe('login', () => {
    it('should authenticate and issue tokens', async () => {
      const hashedPassword = await bcrypt.hash('Secret123!', 10);
      const user = mockUser({ password: hashedPassword, roles: ['admin'] });
      usersService.findByEmail.mockResolvedValue(user);
      jwtService.signAsync.mockResolvedValueOnce('access-token');
      sessionService.create.mockResolvedValue({} as any);

      const result = await service.login(
        { email: 'USER@example.com', password: 'Secret123!' },
        'agent',
        '1.1.1.1',
        'Earth',
      );

      expect(usersService.findByEmail).toHaveBeenCalledWith('user@example.com');
      expect(jwtService.signAsync).toHaveBeenCalledWith(
        { sub: user.id, email: user.email, roles: user.roles },
        { secret: 'access-secret', expiresIn: '15m' },
      );
      expect(sessionService.create).toHaveBeenCalledWith(
        user,
        expect.any(String),
        'agent',
        '1.1.1.1',
        'Earth',
        expect.any(Date),
      );
      expect(result).toMatchObject({
        message: 'Login successful',
        userId: user.id,
        accessToken: 'access-token',
      });
      expect(result.refreshToken).toBeDefined();
    });

    it('should throw NotFoundException when user is missing', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      await expect(
        service.login({ email: 'missing@example.com', password: 'secret' }),
      ).rejects.toBeInstanceOf(NotFoundException);
    });

    it('should throw UnauthorizedException for incorrect password', async () => {
      const hashedPassword = await bcrypt.hash('Correct1!', 10);
      usersService.findByEmail.mockResolvedValue(mockUser({ password: hashedPassword }));

      await expect(
        service.login({ email: 'user@example.com', password: 'Wrong!' }),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });
  });

  describe('refreshToken', () => {
    it('should issue new access token for valid refresh session', async () => {
      const session = {
        id: 'session-id',
        refreshToken: 'hashed-token',
        expiresAt: new Date(Date.now() + 10000),
        status: 'active',
        user: mockUser({ roles: ['user'] }),
      };
      sessionRepo.find.mockResolvedValue([session]);
      jest.spyOn(bcrypt as any, 'compare').mockResolvedValueOnce(true);
      jwtService.signAsync.mockResolvedValueOnce('new-access-token');

      const result = await service.refreshToken('plain-refresh', 'user-id');

      expect(sessionRepo.find).toHaveBeenCalledWith({
        where: { status: 'active', user: { id: 'user-id' } },
        relations: ['user'],
      });
      expect(jwtService.signAsync).toHaveBeenCalledWith(
        { sub: session.user.id, email: session.user.email, roles: session.user.roles },
        { secret: 'access-secret', expiresIn: '15m' },
      );
      expect(result).toEqual({ accessToken: 'new-access-token' });
    });

    it('should throw when refresh token does not match any session', async () => {
      sessionRepo.find.mockResolvedValue([]);

      await expect(service.refreshToken('plain', 'user-id')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });
  });

  describe('requestPasswordReset', () => {
    it('should return generic message when user not found', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      const result = await service.requestPasswordReset('ghost@example.com');

      expect(result).toEqual({
        message: 'If an account exists for this email, reset instructions have been sent.',
      });
      expect(jwtService.signAsync).not.toHaveBeenCalled();
    });

    it('should return reset token for existing user', async () => {
      const user = mockUser();
      usersService.findByEmail.mockResolvedValue(user);
      jwtService.signAsync.mockResolvedValueOnce('reset-token');

      const result = await service.requestPasswordReset('user@example.com');

      expect(jwtService.signAsync).toHaveBeenCalledWith(
        { sub: user.id, email: user.email, type: 'password-reset' },
        { secret: 'reset-secret', expiresIn: '10m' },
      );
      expect(result).toMatchObject({
        message: 'Password reset instructions generated successfully.',
        resetToken: 'reset-token',
      });
    });
  });

  describe('changePassword', () => {
    it('should update password and revoke sessions', async () => {
      const hashedPassword = await bcrypt.hash('OldPass1!', 10);
      usersService.findById.mockResolvedValue(mockUser({ password: hashedPassword }));

      await service.changePassword('user-id', 'OldPass1!', 'NewPass1!');

      expect(usersService.updateUser).toHaveBeenCalledWith(
        'user-id',
        expect.objectContaining({ password: expect.any(String) }),
      );
      const updatedPassword = usersService.updateUser.mock.calls[0][1].password;
      expect(updatedPassword).not.toBe('NewPass1!');
      expect(sessionService.revoke).toHaveBeenCalledWith('user-id');
    });

    it('should throw UnauthorizedException for incorrect current password', async () => {
      const hashedPassword = await bcrypt.hash('Correct1!', 10);
      usersService.findById.mockResolvedValue(mockUser({ password: hashedPassword }));

      await expect(
        service.changePassword('user-id', 'WrongPass!', 'NewPass1!'),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });
  });

  describe('verifyEmail', () => {
    it('should mark user as verified when token valid', async () => {
      jwtService.verifyAsync.mockResolvedValueOnce({
        sub: 'user-id',
        type: 'email-verification',
      });
      usersService.findById.mockResolvedValue(mockUser({ isVerified: false }));

      await service.verifyEmail('token');

      expect(usersService.updateUser).toHaveBeenCalledWith('user-id', { isVerified: true });
    });

    it('should throw BadRequestException when token invalid', async () => {
      jwtService.verifyAsync.mockRejectedValueOnce(new Error('invalid'));

      await expect(service.verifyEmail('bad-token')).rejects.toBeInstanceOf(BadRequestException);
    });

    it('should throw BadRequestException when token type mismatch', async () => {
      jwtService.verifyAsync.mockResolvedValueOnce({ sub: 'user-id', type: 'wrong' });

      await expect(service.verifyEmail('token')).rejects.toBeInstanceOf(BadRequestException);
    });
  });

  describe('profile helpers', () => {
    it('getProfile should return sanitized user', async () => {
      const user = mockUser({ password: 'secret-hash', isVerified: true });
      usersService.findById.mockResolvedValue(user);

      const result = await service.getProfile('user-id');

      expect(result).toMatchObject({
        id: user.id,
        email: user.email,
        name: user.name,
        isVerified: true,
      });
      expect(result).not.toHaveProperty('password');
    });

    it('getUserRoles should return role payload', async () => {
      const user = mockUser({ roles: ['admin', 'user'] });
      usersService.findById.mockResolvedValue(user);

      const result = await service.getUserRoles('user-id');

      expect(result).toEqual({ roles: ['admin', 'user'] });
    });

    it('should throw NotFoundException when user missing for profile', async () => {
      usersService.findById.mockResolvedValue(null);

      await expect(service.getProfile('missing')).rejects.toBeInstanceOf(NotFoundException);
    });
  });
});
