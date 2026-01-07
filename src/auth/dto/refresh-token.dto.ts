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
    example: '039964b8-fef4-4058-855e-a092532043c9',
  })
  @IsNotEmpty()
  @IsUUID()
  userId: string;
}
