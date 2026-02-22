import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ConfirmPasswordResetDto {
  @ApiProperty({
    description: 'Password reset token delivered to the user email address',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsNotEmpty()
  @IsString()
  token: string;

  @ApiProperty({
    example: 'newEvenStrongerPassword!2',
    description: 'New password to set for the account',
  })
  @IsNotEmpty()
  @MinLength(6)
  newPassword: string;
}
