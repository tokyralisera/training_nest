import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private async transporter() {
    const testAccount = await nodemailer.createTestAccount();
    const transport = nodemailer.createTransport({
      host: 'localhost',
      port: 1025,
      ignoreTLS: true,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
    });
    return transport
  }

  async sendSignupConfirmation(userEmail: string){
    (await this.transporter()).sendMail({
        from: "app@localhost.com",
        to: userEmail,
        subject: "Inscription",
        html: "<h3>Inscription terminee</h3>"
    })
  }

  async sendResetPassword(userEmail: string, url: string, code: string) {
    (await this.transporter()).sendMail({
      from: "app@localhost.com",
      to: userEmail,
      subject: "Reinitialisation du mot de passe",
      html: `
        <a href="${url}">Reinitialisation du mot de passe</a>
        <p>Code secret <strong>${code}</strong></p>
      `,
    });
  }  
}
