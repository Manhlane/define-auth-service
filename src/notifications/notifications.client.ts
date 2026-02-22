import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

type WelcomePayload = {
  email: string;
  name?: string;
  verificationUrl?: string;
};

type PasswordResetPayload = {
  email: string;
  name?: string;
  resetUrl: string;
  expiresInMinutes?: number;
  supportUrl?: string;
};

@Injectable()
export class NotificationsClient {
  private readonly logger = new Logger(NotificationsClient.name);
  private readonly baseUrl: string;
  private readonly dashboardUrl: string;

  constructor(private readonly configService: ConfigService) {
    this.baseUrl = this.normalizeBaseUrl(
      this.configService.get<string>('NOTIFICATIONS_URL') ??
        'http://localhost:3005/notifications',
    );
    const appBase =
      this.configService.get<string>('APP_BASE_URL') ??
      'http://34.251.72.37:3002';
    this.dashboardUrl = this.resolveUrl(appBase, '/dashboard');
  }

  async sendWelcomeEmail(payload: WelcomePayload): Promise<void> {
    await this.post('/auth/welcome', {
      email: payload.email,
      name: payload.name,
      verificationUrl: payload.verificationUrl,
      dashboardUrl: this.dashboardUrl,
    });
  }

  async sendPasswordResetEmail(payload: PasswordResetPayload): Promise<void> {
    await this.post('/auth/password-reset', {
      email: payload.email,
      name: payload.name,
      resetUrl: payload.resetUrl,
      expiresInMinutes: payload.expiresInMinutes,
      supportUrl: payload.supportUrl,
    });
  }

  private normalizeBaseUrl(url: string): string {
    return url.endsWith('/') ? url.slice(0, -1) : url;
  }

  private resolveUrl(base: string, path: string): string {
    try {
      const target = new URL(path, base);
      return target.toString();
    } catch (error) {
      this.logger.warn(
        `Failed to resolve URL for base ${base} and path ${path}: ${error}`,
      );
      return `${base.replace(/\/$/, '')}${path}`;
    }
  }

  private async post(path: string, body: unknown): Promise<void> {
    const url = `${this.baseUrl}${path}`;

    const fetchImpl = this.getFetch();

    try {
      const response = await fetchImpl(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const text = await response.text();
        this.logger.warn(
          `Notifications service responded with ${response.status}: ${text}`,
        );
      }
    } catch (error) {
      this.logger.warn(
        `Failed to reach notifications service at ${url}`,
        error as Error,
      );
    }
  }

  private getFetch(): typeof fetch {
    if (typeof fetch === 'function') {
      return fetch;
    }

    throw new Error('Fetch API is not available in this environment.');
  }
}
