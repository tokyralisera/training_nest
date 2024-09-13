import { IsNotEmpty, IsOptional } from "class-validator";

export class UpdatePostDto {
    @IsNotEmpty()
    @IsOptional()
    readonly title? : string

    @IsNotEmpty()
    @IsOptional()
    readonly body? : string
}