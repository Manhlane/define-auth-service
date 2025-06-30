import { Body, Controller, Get, Post, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RegisterDto } from './dto/register.dto';


@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

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

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiOperation({ summary: 'Get authenticated user profile' })
  @ApiResponse({ status: 200, description: 'User profile returned' })
  async profile(@Req() req) {
    // return req.user;
  }

  @Post('refresh-token')
  @ApiOperation({ summary: 'Generate new access token using refresh token' })
  @ApiResponse({ status: 200, description: 'New access token issued' })
  async refreshToken(@Body() body: any) {
    // return this.authService.refreshToken(body.refreshToken);
  }

  @Post('logout')
  @ApiOperation({ summary: 'Log out user and clear token' })
  @ApiResponse({ status: 200, description: 'Logged out successfully' })
  async logout(@Body() body: any) {
    // return this.authService.logout(body.refreshToken);
  }

  @Post('forgot-password')
  @ApiOperation({ summary: 'Send password reset instructions to user email' })
  @ApiResponse({ status: 200, description: 'Reset link sent' })
  async forgotPassword(@Body() body: any) {
    // return this.authService.sendResetEmail(body.email);
  }

  @Post('change-password')
  @ApiOperation({ summary: 'Change password for authenticated user' })
  @ApiResponse({ status: 200, description: 'Password changed successfully' })
  async changePassword(@Body() body: any) {
    // return this.authService.changePassword(body);
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
