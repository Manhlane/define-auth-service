import {
  Controller,
  Delete,
  Get,
  Param,
  HttpCode,
  HttpStatus,
  Logger,
  Req,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { SessionService } from './session.service';
import { Session } from './entities/session.entity';
import { Request } from 'express';

@ApiTags('Sessions')
@Controller('sessions')
export class SessionController {
  private readonly logger = new Logger(SessionController.name);

  constructor(private readonly sessionService: SessionService) {}

  private extractRequestMeta(req: Request) {
    const forwarded = req.headers['x-forwarded-for'];
    const forwardedValue = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    const ip =
      forwardedValue?.split(',')[0]?.trim() ||
      req.ip ||
      req.socket?.remoteAddress ||
      undefined;
    const userAgent = req.headers['user-agent'];
    return {
      ip,
      userAgent: typeof userAgent === 'string' ? userAgent : undefined,
    };
  }

  @Get('user/:userId')
  @ApiOperation({ summary: 'Get all active sessions for a user' })
  @ApiParam({ name: 'userId', type: String, description: 'User ID' })
  @ApiResponse({
    status: 200,
    description: 'List of active sessions',
    type: [Session],
  })
  async getActiveSessions(
    @Param('userId') userId: string,
    @Req() req: Request,
  ): Promise<Session[]> {
    const meta = this.extractRequestMeta(req);
    const sessions = await this.sessionService.getActiveSessions(userId);
    this.logger.log({
      event: 'SESSIONS_LISTED',
      userId,
      count: sessions.length,
      ip: meta.ip,
      userAgent: meta.userAgent,
    });
    return sessions;
  }

  @Delete('user/:userId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke all sessions for a user' })
  @ApiParam({ name: 'userId', type: String, description: 'User ID' })
  @ApiResponse({ status: 204, description: 'All sessions revoked' })
  async revokeAllSessions(
    @Param('userId') userId: string,
    @Req() req: Request,
  ): Promise<void> {
    const meta = this.extractRequestMeta(req);
    await this.sessionService.revoke(userId);
    this.logger.log({
      event: 'SESSIONS_REVOKED_ALL',
      userId,
      ip: meta.ip,
      userAgent: meta.userAgent,
    });
  }

  @Delete(':sessionId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke a single session' })
  @ApiParam({ name: 'sessionId', type: String, description: 'Session ID' })
  @ApiResponse({ status: 204, description: 'Session revoked' })
  async revokeSession(
    @Param('sessionId') sessionId: string,
    @Req() req: Request,
  ): Promise<void> {
    const meta = this.extractRequestMeta(req);
    await this.sessionService.revokeSingleSession(sessionId);
    this.logger.log({
      event: 'SESSION_REVOKED',
      sessionId,
      ip: meta.ip,
      userAgent: meta.userAgent,
    });
  }
}
