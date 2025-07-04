// src/auth/dto/refresh-token.dto.ts
import { IsNotEmpty, IsString, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RefreshTokenDto {
  @ApiProperty({
    description: 'Refresh token received at login',
    example: '6e471447-8e63-472e-8f9e-2c375427aa36',
  })
  @IsNotEmpty()
  @IsString()
  refreshToken: string;

  @ApiProperty({
    description: 'ID of the user associated with this refresh token',
    example: 'f34b1f4e-9c6c-4d2a-a77e-b41dafe1f7aa',
  })
  @IsNotEmpty()
  @IsUUID()
  userId: string;
}
