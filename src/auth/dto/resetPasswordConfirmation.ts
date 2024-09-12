import { IsNotEmpty, IsEmail, isNotEmpty } from "class-validator"
 
export class ResetPasswordConfirmationDto {
    @IsNotEmpty()
    @IsEmail()
    readonly email : string
    
    @IsNotEmpty()
    readonly password : string

    @IsNotEmpty()
    readonly code : string
}