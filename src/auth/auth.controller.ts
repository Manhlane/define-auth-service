import {
  Body,
  Controller,
  Get,
  Post,
  UseGuards,
  Req,
  Res,
  Logger,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RegisterDto } from './dto/register.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response } from 'express';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  private normalizeIpAddress(ipAddress?: string): string | undefined {
    if (!ipAddress) return undefined;
    const trimmed = ipAddress.trim();
    if (trimmed.startsWith('::ffff:')) {
      return trimmed.replace('::ffff:', '');
    }
    const ipv4WithPort = trimmed.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/);
    if (ipv4WithPort) {
      return ipv4WithPort[1];
    }
    return trimmed;
  }

  private isPrivateIp(ipAddress?: string): boolean {
    if (!ipAddress) return true;
    if (ipAddress === '::1') return true;
    if (ipAddress.startsWith('::ffff:')) {
      return this.isPrivateIp(ipAddress.replace('::ffff:', ''));
    }
    if (ipAddress.startsWith('10.')) return true;
    if (ipAddress.startsWith('127.')) return true;
    if (ipAddress.startsWith('192.168.')) return true;
    if (ipAddress.startsWith('169.254.')) return true;
    if (ipAddress.startsWith('0.')) return true;
    if (ipAddress.startsWith('fc') || ipAddress.startsWith('fd')) return true;
    if (ipAddress.startsWith('fe80:')) return true;
    const octets = ipAddress.split('.');
    if (octets.length === 4) {
      const [first, second] = octets.map((value) => parseInt(value, 10));
      if (first === 172 && second >= 16 && second <= 31) return true;
      if (first === 100 && second >= 64 && second <= 127) return true;
    }
    return false;
  }

  private async lookupGeoLocation(ipAddress?: string): Promise<string | undefined> {
    const normalizedIp = this.normalizeIpAddress(ipAddress);
    if (!normalizedIp || this.isPrivateIp(normalizedIp)) {
      return undefined;
    }

    const baseUrl = process.env.GEOIP_LOOKUP_URL ?? 'https://ipapi.co';
    const url = baseUrl.includes('{ip}')
      ? baseUrl.replace('{ip}', normalizedIp)
      : `${baseUrl.replace(/\/$/, '')}/${normalizedIp}/json/`;
    const timeoutMs = Number(process.env.GEOIP_LOOKUP_TIMEOUT_MS ?? '800');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { accept: 'application/json' },
      });
      if (!res.ok) return undefined;
      const payload = (await res.json().catch(() => null)) as any;
      if (!payload || payload.error || payload.bogon) return undefined;

      const city = payload.city || payload.city_name;
      const region =
        payload.region ||
        payload.region_name ||
        payload.state ||
        payload.region_code;
      const country =
        payload.country_code ||
        payload.country ||
        payload.country_code2 ||
        payload.country_name;

      const parts = [city, region, country]
        .filter((value) => typeof value === 'string' && value.trim().length > 0)
        .map((value) => (value as string).trim());

      return parts.length ? parts.join(', ') : undefined;
    } catch (error) {
      this.logger.debug(`Geo lookup failed: ${error}`);
      return undefined;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async extractRequestMetadata(req: Request): Promise<{
    userAgent?: string;
    ipAddress?: string;
    location?: string;
  }> {
    const forwarded = req.headers['x-forwarded-for'];
    const forwardedValue = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    const ipAddress = this.normalizeIpAddress(
      forwardedValue?.split(',')[0]?.trim() ||
        req.ip ||
        req.socket?.remoteAddress ||
        undefined,
    );
    const userAgent = req.headers['user-agent'];

    const country =
      req.headers['x-vercel-ip-country'] ||
      req.headers['cf-ipcountry'] ||
      req.headers['cloudfront-viewer-country'] ||
      req.headers['x-country-code'] ||
      req.headers['x-country'];
    const region =
      req.headers['x-vercel-ip-region'] ||
      req.headers['x-region'] ||
      req.headers['x-country-region'];
    const city =
      req.headers['x-vercel-ip-city'] ||
      req.headers['x-city'] ||
      req.headers['x-geo-city'];

    const locationParts = [city, region, country]
      .filter((value) => typeof value === 'string' && value.trim().length > 0)
      .map((value) => (value as string).trim());
    let location = locationParts.length ? locationParts.join(', ') : undefined;

    if (!location) {
      location = await this.lookupGeoLocation(ipAddress);
    }
    return {
      userAgent: typeof userAgent === 'string' ? userAgent : undefined,
      ipAddress,
      location,
    };
  }

  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @ApiBody({ type: RegisterDto })
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('login')
  @ApiOperation({ summary: 'Authenticate user and return access token' })
  @ApiResponse({ status: 200, description: 'Access token returned' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiBody({ type: LoginDto })
  async login(@Body() loginDto: LoginDto, @Req() req: Request) {
    const metadata = await this.extractRequestMetadata(req);
    return this.authService.login(
      loginDto,
      metadata.userAgent,
      metadata.ipAddress,
      metadata.location,
    );
  }

  @Post('refresh-token')
  @ApiOperation({ summary: 'Generate new access token using refresh token' })
  @ApiResponse({ status: 200, description: 'New access token issued' })
  @ApiBody({ type: RefreshTokenDto })
  async refreshToken(@Body() dto: RefreshTokenDto) {
    return this.authService.refreshToken(dto.refreshToken, dto.userId);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Log out user and clear token' })
  @ApiResponse({ status: 200, description: 'Logged out successfully' })
  async logout(@Req() req: Request) {
    const user = req.user as { id: string };
    return this.authService.logout(user.id);
  }

  @Post('forgot-password')
  @ApiOperation({ summary: 'Send password reset instructions to user email' })
  @ApiResponse({ status: 200, description: 'Reset link sent' })
  @ApiBody({ type: ForgotPasswordDto })
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.requestPasswordReset(dto.email);
  }

  @Post('resend-verification')
  @ApiOperation({ summary: 'Generate a fresh email verification token' })
  @ApiResponse({
    status: 200,
    description: 'Verification token generated successfully',
  })
  @ApiBody({ type: ResendVerificationDto })
  async resendVerification(@Body() dto: ResendVerificationDto) {
    return this.authService.resendVerification(dto.email);
  }

  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Change password for authenticated user' })
  @ApiResponse({ status: 200, description: 'Password changed successfully' })
  @ApiBody({ type: ChangePasswordDto })
  async changePassword(@Body() dto: ChangePasswordDto, @Req() req: Request) {
    const user = req.user as { id: string };
    await this.authService.changePassword(
      user.id,
      dto.currentPassword,
      dto.newPassword,
    );
    return { message: 'Password changed successfully' };
  }

  @Post('verify-email')
  @ApiOperation({ summary: 'Verify user email using token' })
  @ApiResponse({ status: 200, description: 'Email verified successfully' })
  @ApiBody({ type: VerifyEmailDto })
  async verifyEmail(@Body() dto: VerifyEmailDto) {
    await this.authService.verifyEmail(dto.token);
    return { message: 'Email verified successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiOperation({ summary: 'Get current authenticated user info' })
  @ApiResponse({ status: 200, description: 'User info returned' })
  async me(@Req() req: Request) {
    const user = req.user as { id: string };
    return this.authService.getProfile(user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Get('roles')
  @ApiOperation({ summary: 'Get roles/permissions of authenticated user' })
  @ApiResponse({ status: 200, description: 'User roles returned' })
  async roles(@Req() req: Request) {
    const user = req.user as { id: string };
    return this.authService.getUserRoles(user.id);
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth(): Promise<void> {
    return;
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req: Request, @Res() res: Response) {
    const metadata = await this.extractRequestMetadata(req);
    const result = await this.authService.loginWithGoogle(
      req.user,
      metadata.userAgent,
      metadata.ipAddress,
      metadata.location,
    );

    if (result.user) {
      this.logger.log(
        `Google OAuth user authenticated: ${JSON.stringify(result.user)}`,
      );
    }

    const dashboardUrl = new URL('http://localhost:3000/dashboard');

    if (result.user) {
      dashboardUrl.searchParams.set('userId', result.user.id);
      if (result.user.email) {
        dashboardUrl.searchParams.set('email', result.user.email);
      }
      if (result.user.name) {
        dashboardUrl.searchParams.set('name', result.user.name);
      }
    }

    dashboardUrl.searchParams.set('accessToken', result.accessToken);
    dashboardUrl.searchParams.set('refreshToken', result.refreshToken);

    return res.redirect(dashboardUrl.toString());
  }
}
