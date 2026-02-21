import { ApiProperty } from '@nestjs/swagger';
import { IsUUID } from 'class-validator';

export class LogoutDto {
  @ApiProperty({
    example: '039964b8-fef4-4058-855e-a092532043c9',
    description: 'Session Id',
  })
  @IsUUID()
  sessionId: string;
}
