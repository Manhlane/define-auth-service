import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class UpdateProfileDto {
  @ApiPropertyOptional({
    example: 'user@example.com',
    description: 'Email address for the user account',
  })
  @IsOptional()
  @IsEmail()
  @MaxLength(180)
  email?: string;

  @ApiPropertyOptional({
    example: 'Manhlane Mamabolo',
    description: 'Display name for the user account',
  })
  @IsOptional()
  @IsString()
  @MinLength(2)
  @MaxLength(120)
  name?: string;

  @ApiPropertyOptional({
    example: 'Manhlane Photography',
    nullable: true,
    description: 'Optional business name shown on payment links and profile',
  })
  @IsOptional()
  @IsString()
  @MaxLength(160)
  businessName?: string | null;

  @ApiPropertyOptional({
    example: '+27 71 123 4567',
    nullable: true,
    description: 'Optional phone number for the profile',
  })
  @IsOptional()
  @IsString()
  @MaxLength(40)
  phone?: string | null;

  @ApiPropertyOptional({
    example: 'FNB',
    nullable: true,
    description: 'Optional bank name used for payouts',
  })
  @IsOptional()
  @IsString()
  @MaxLength(120)
  bankName?: string | null;

  @ApiPropertyOptional({
    example: '1234567890',
    nullable: true,
    description: 'Optional bank account number used for payouts',
  })
  @IsOptional()
  @IsString()
  @MaxLength(64)
  accountNumber?: string | null;

  @ApiPropertyOptional({
    example: 'savings',
    nullable: true,
    description: 'Optional bank account type used for payouts',
  })
  @IsOptional()
  @IsString()
  @MaxLength(40)
  accountType?: string | null;

  @ApiPropertyOptional({
    example: 'data:image/png;base64,...',
    nullable: true,
    description: 'Optional profile image URL or data URL',
  })
  @IsOptional()
  @IsString()
  @MaxLength(2800000)
  avatarUrl?: string | null;
}
