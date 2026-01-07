import {
  Controller,
  Delete,
  Get,
  Param,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { SessionService } from './session.service';
import { Session } from './entities/session.entity';

@ApiTags('Sessions')
@Controller('sessions')
export class SessionController {
  constructor(private readonly sessionService: SessionService) {}

  @Get('user/:userId')
  @ApiOperation({ summary: 'Get all active sessions for a user' })
  @ApiParam({ name: 'userId', type: String, description: 'User ID' })
  @ApiResponse({
    status: 200,
    description: 'List of active sessions',
    type: [Session],
  })
  async getActiveSessions(@Param('userId') userId: string): Promise<Session[]> {
    return this.sessionService.getActiveSessions(userId);
  }

  @Delete('user/:userId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke all sessions for a user' })
  @ApiParam({ name: 'userId', type: String, description: 'User ID' })
  @ApiResponse({ status: 204, description: 'All sessions revoked' })
  async revokeAllSessions(@Param('userId') userId: string): Promise<void> {
    await this.sessionService.revoke(userId);
  }

  @Delete(':sessionId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke a single session' })
  @ApiParam({ name: 'sessionId', type: String, description: 'Session ID' })
  @ApiResponse({ status: 204, description: 'Session revoked' })
  async revokeSession(@Param('sessionId') sessionId: string): Promise<void> {
    await this.sessionService.revokeSingleSession(sessionId);
  }
}
