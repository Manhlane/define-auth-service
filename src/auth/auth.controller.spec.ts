import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: {
    register: jest.Mock;
    login: jest.Mock;
    loginWithGoogle: jest.Mock;
    refreshToken: jest.Mock;
    logout: jest.Mock;
    requestPasswordReset: jest.Mock;
    changePassword: jest.Mock;
    verifyEmail: jest.Mock;
    getProfile: jest.Mock;
    getUserRoles: jest.Mock;
  };

  beforeEach(async () => {
    authService = {
      register: jest.fn(),
      login: jest.fn(),
      loginWithGoogle: jest.fn(),
      refreshToken: jest.fn(),
      logout: jest.fn(),
      requestPasswordReset: jest.fn(),
      changePassword: jest.fn(),
      verifyEmail: jest.fn(),
      getProfile: jest.fn(),
      getUserRoles: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: authService,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('passes request metadata to login', async () => {
    const loginDto = { email: 'user@example.com', password: 'secret' };
    const req = {
      headers: {
        'user-agent': 'Mozilla/5.0',
        'x-forwarded-for': '203.0.113.1, 70.41.3.18',
        'x-vercel-ip-city': 'Cape Town',
        'x-vercel-ip-region': 'WC',
        'x-vercel-ip-country': 'ZA',
      },
      ip: '10.0.0.2',
      socket: { remoteAddress: '10.0.0.3' },
    } as any;

    authService.login.mockResolvedValue({ ok: true });

    await controller.login(loginDto as any, req);

    expect(authService.login).toHaveBeenCalledWith(
      loginDto,
      'Mozilla/5.0',
      '203.0.113.1',
      'Cape Town, WC, ZA',
    );
  });

  it('passes request metadata to Google login and redirects', async () => {
    const req = {
      user: { id: 'user-1' },
      headers: {
        'user-agent': 'GoogleBot',
        'x-forwarded-for': '198.51.100.2',
        'x-vercel-ip-country': 'US',
      },
      ip: '10.0.0.4',
    } as any;
    const res = { redirect: jest.fn() } as any;

    authService.loginWithGoogle.mockResolvedValue({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      user: { id: 'user-1', email: 'user@example.com', name: 'User' },
    });

    await controller.googleAuthRedirect(req, res);

    expect(authService.loginWithGoogle).toHaveBeenCalledWith(
      req.user,
      'GoogleBot',
      '198.51.100.2',
      'US',
    );
    expect(res.redirect).toHaveBeenCalledWith(
      expect.stringContaining('accessToken=access-token'),
    );
    expect(res.redirect).toHaveBeenCalledWith(
      expect.stringContaining('refreshToken=refresh-token'),
    );
    expect(res.redirect).toHaveBeenCalledWith(
      expect.stringContaining('userId=user-1'),
    );
  });
});
