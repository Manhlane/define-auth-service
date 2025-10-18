import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, MinLength } from 'class-validator';

export class ChangePasswordDto {
  @ApiProperty({ example: 'oldStrongPassword!1', description: 'Current password of the authenticated user' })
  @IsNotEmpty()
  currentPassword: string;

  @ApiProperty({ example: 'newEvenStrongerPassword!2', description: 'New password to set for the account' })
  @IsNotEmpty()
  @MinLength(6)
  newPassword: string;
}
