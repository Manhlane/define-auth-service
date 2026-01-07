import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class ResendVerificationDto {
  @ApiProperty({
    description: 'Email that should receive a fresh verification link',
  })
  @IsEmail()
  @IsNotEmpty()
  email!: string;
}
