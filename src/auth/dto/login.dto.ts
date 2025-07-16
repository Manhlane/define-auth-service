// src/auth/dto/login.dto.ts
import { IsEmail, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'tlhax@define.com', description: 'User email address' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: '12345', description: 'User password' })
  @IsNotEmpty()
  password: string;
}