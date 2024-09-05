import { IsNotEmpty, IsEmail, isNotEmpty } from "class-validator"
 
export class SigninDto {
    @IsNotEmpty()
    readonly username: string
    
    @IsNotEmpty()
    @IsEmail()
    readonly email : string
    
    @IsNotEmpty()
    readonly password : string
}