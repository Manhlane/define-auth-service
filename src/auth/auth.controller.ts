import { Body, Controller, Get, Post, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RegisterDto } from './dto/register.dto';
import { UsersService } from 'src/users/users.service';
import { RefreshTokenDto } from './dto/refresh-token.dto';


@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService, private readonly usersService: UsersService) { }

  @Post('login')
  @ApiOperation({ summary: 'Authenticate user and return access token' })
  @ApiResponse({ status: 200, description: 'Access token returned' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiBody({ type: LoginDto })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @ApiBody({ type: RegisterDto })
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiOperation({ summary: 'Get authenticated user profile' })
  @ApiResponse({ status: 200, description: 'User profile returned' })
  async profile(@Req() req) {
    const user = await this.usersService.findById(req.user.id);
    return {
      id: user.id,
      email: user.email,
      name: user.name,
    };
  }

  @Post('refresh-token')
  @ApiOperation({ summary: 'Generate new access token using refresh token' })
  @ApiResponse({ status: 200, description: 'New access token issued' })
  @ApiBody({ type: RefreshTokenDto })
  async refreshToken(@Body() dto: RefreshTokenDto) {
    console.log("Refresh Token: " + dto.refreshToken)
    //do null checks
    return this.authService.refreshToken(dto.refreshToken, dto.userId);
  }

  @Post('logout')
  @ApiOperation({ summary: 'Log out user and clear token' })
  @ApiResponse({ status: 200, description: 'Logged out successfully' })
  async logout(@Body() body: any) {
    //return this.authService.logout(body.refreshToken);
  }

  @Post('forgot-password')
  @ApiOperation({ summary: 'Send password reset instructions to user email' })
  @ApiResponse({ status: 200, description: 'Reset link sent' })
  async forgotPassword(@Body() body: any) {
    //return this.authService.sendResetEmail(body.email);
  }

  @Post('change-password')
  @ApiOperation({ summary: 'Change password for authenticated user' })
  @ApiResponse({ status: 200, description: 'Password changed successfully' })
  async changePassword(@Body() body: any) {
    //return this.authService.changePassword(body);
  }

  @Post('verify-email')
  @ApiOperation({ summary: 'Verify user email using token' })
  @ApiResponse({ status: 200, description: 'Email verified successfully' })
  async verifyEmail(@Body() body: any) {
    // return this.authService.verifyEmail(body.token);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiOperation({ summary: 'Get current authenticated user info' })
  @ApiResponse({ status: 200, description: 'User info returned' })
  async me(@Req() req) {
    // return req.user;
  }

  @UseGuards(JwtAuthGuard)
  @Get('roles')
  @ApiOperation({ summary: 'Get roles/permissions of authenticated user' })
  @ApiResponse({ status: 200, description: 'User roles returned' })
  async roles(@Req() req) {
    // return this.authService.getUserRoles(req.user.id);
  }
}
