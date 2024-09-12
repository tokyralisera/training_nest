import { Body, Controller, Delete, Post, Req, UseGuards } from '@nestjs/common';
import { SignupDto } from './dto/signupDto';
import { AuthService } from './auth.service';
import { SigninDto } from './dto/signinDto';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemandDto';
import { ResetPasswordConfirmationDto } from './dto/resetPasswordConfirmation';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { DeleteAccountDto } from './dto/deleteAccountDto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() signupDto: SignupDto) {
    return this.authService.signup(signupDto);
  }

  @Post('signin')
  signin(@Body() signinDto: SigninDto) {
    return this.authService.signin(signinDto);
  }

  @Post('reset-password')
  resetPassword(@Body() resetPasswordDemand: ResetPasswordDemandDto){
    return this.authService.resetPasswordDemand(resetPasswordDemand)
  }

  @Post('reset-password-confirmation')
  resetPasswordConfirmation(@Body() resetPasswordConfirmationDto : ResetPasswordConfirmationDto){
    return this.authService.resetPasswordConfirmation(resetPasswordConfirmationDto)
  }

  @UseGuards(AuthGuard("jwt"))
  @Delete("delete")
  deleteAccount(@Req() request : Request, @Body() deleteAccountDto: DeleteAccountDto){
    const userId =  request.user["userId"];
    return this.authService.deleteAccount(userId, deleteAccountDto)
  }
}
