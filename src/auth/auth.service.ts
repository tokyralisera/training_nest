import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
  InternalServerErrorException,
} from '@nestjs/common';
import { SignupDto } from './dto/signupDto';
import { SigninDto } from './dto/signinDto';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemandDto';
import { ResetPasswordConfirmationDto } from './dto/resetPasswordConfirmation';
import { DeleteAccountDto } from './dto/deleteAccountDto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import * as speakeasy from 'speakeasy';
import { MailerService } from 'src/mailer/mailer.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  private readonly jwtSecret: string;
  private readonly otpSecret: string;
  private readonly jwtExpiration: string;

  constructor(
    private readonly prismaService: PrismaService,
    private readonly mailerService: MailerService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {
    this.jwtSecret = this.configService.get<string>('SECRET_KEY');
    this.otpSecret = this.configService.get<string>('OTP_CODE');
    this.jwtExpiration = '12h';
  }

  /**
   * Enregistre un nouvel utilisateur.
   */
  async signup(signupDto: SignupDto) {
    const { email, password, username } = signupDto;
    try {
      await this.checkUserDoesNotExist(email);
      const hashedPassword = await this.hashPassword(password);
      await this.createUser({ email, username, password: hashedPassword });
      try {
        await this.mailerService.sendSignupConfirmation(email);
      } catch (emailError) {
        console.error('Erreur lors de l\'envoi de l\'email de confirmation d\' inscription:', emailError.message);
      }
      return { data: 'User created successfully' };
    } catch (error) {
      this.handleError(error, 'signup');
    }
  }

  /**
   * Connecte un utilisateur existant.
   */
  async signin(signinDto: SigninDto) {
    const { email, password, username } = signinDto;
    try {
      const user = await this.getUserByEmail(email);
      this.verifyUsername(user, username);
      await this.verifyPassword(password, user.password);
      const token = this.generateJwtToken(user);
      return { token, user: { username: user.username, email: user.email } };
    } catch (error) {
      this.handleError(error, 'signin');
    }
  }

  /**
   * Gère la demande de réinitialisation de mot de passe.
   */
  async resetPasswordDemand(resetPasswordDemandDto: ResetPasswordDemandDto) {
    const { email } = resetPasswordDemandDto;
    try {
      await this.getUserByEmail(email);
      const code = this.generateOtpCode();
      const url = 'http://localhost:3000/auth/reset-password-confirmation';
      await this.mailerService.sendResetPassword(email, url, code);
      return { data: 'Reset password email has been sent' };
    } catch (error) {
      this.handleError(error, 'resetPasswordDemand');
    }
  }

  /**
   * Confirme la réinitialisation de mot de passe.
   */
  async resetPasswordConfirmation(
    resetPasswordConfirmationDto: ResetPasswordConfirmationDto,
  ) {
    const { email, code, password } = resetPasswordConfirmationDto;
    try {
      await this.getUserByEmail(email);
      this.verifyOtpCode(code);
      const hashedPassword = await this.hashPassword(password);
      await this.updateUserPassword(email, hashedPassword);
      return { data: 'Password changed successfully' };
    } catch (error) {
      this.handleError(error, 'resetPasswordConfirmation');
    }
  }

  /**
   * Supprime un compte utilisateur.
   */
  async deleteAccount(userId: any, deleteAccountDto: DeleteAccountDto) {
    const { password } = deleteAccountDto;
    try {
      const user = await this.getUserById(userId);
      await this.verifyPassword(password, user.password);
      await this.prismaService.user.delete({ where: { userId } });
      return { data: 'User deleted' };
    } catch (error) {
      this.handleError(error, 'deleteAccount');
    }
  }

  // Méthodes privées

  private async checkUserDoesNotExist(email: string): Promise<void> {
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (user) throw new ConflictException('User already exists');
  }

  private async getUserByEmail(email: string) {
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  private async getUserById(userId: any) {
    const user = await this.prismaService.user.findUnique({
      where: { userId },
    });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  private async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  private async createUser(data: {
    email: string;
    username: string;
    password: string;
  }) {
    return await this.prismaService.user.create({ data });
  }

  private verifyUsername(user: any, username: string): void {
    if (user.username !== username)
      throw new UnauthorizedException('Username error');
  }

  private async verifyPassword(
    password: string,
    hashedPassword: string,
  ): Promise<void> {
    const match = await bcrypt.compare(password, hashedPassword);
    if (!match) throw new UnauthorizedException('Password error');
  }

  private generateJwtToken(user: any): string {
    const payload = { sub: user.userId, email: user.email };
    return this.jwtService.sign(payload, {
      expiresIn: this.jwtExpiration,
      secret: this.jwtSecret,
    });
  }

  private generateOtpCode(): string {
    return speakeasy.totp({
      secret: this.otpSecret,
      digits: 5,
      step: 60 * 5,
      encoding: 'base32',
    });
  }

  private verifyOtpCode(code: string): void {
    const isValid = speakeasy.totp.verify({
      secret: this.otpSecret,
      token: code,
      digits: 5,
      step: 60 * 5,
      encoding: 'base32',
    });
    if (!isValid) throw new UnauthorizedException('Invalid or expired token');
  }

  private async updateUserPassword(email: string, hashedPassword: string) {
    await this.prismaService.user.update({
      where: { email },
      data: { password: hashedPassword },
    });
  }

  private handleError(error: any, context: string) {
    if (
      error instanceof ConflictException ||
      error instanceof NotFoundException ||
      error instanceof UnauthorizedException
    ) {
      throw error;
    }
    console.error(`Error in ${context}:`, error);
    throw new InternalServerErrorException('An unexpected error occurred');
  }
}
