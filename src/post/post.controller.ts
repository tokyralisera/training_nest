import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { PostService } from './post.service';
import { AuthGuard } from '@nestjs/passport';
import { CreatePostDto } from './dto/createPostDto';
import { Request } from 'express';
import { UpdatePostDto } from './dto/updatePostDto';

@Controller('posts')
export class PostController {
  constructor(private readonly postService: PostService) {}

  @Get()
  getAll() {
    return this.postService.getAll();
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('create')
  create(@Body() createPostDto: CreatePostDto, @Req() request: Request) {
    const userId = request.user['userId'];
    return this.postService.create(createPostDto, userId);
  }

  @UseGuards(AuthGuard('jwt'))
  @Put('update/:id')
  update(
    @Param('id', ParseIntPipe) postID: number,
    @Body() updatePostDto: UpdatePostDto,
    @Req() request: Request,
  ) {
    const userId = request.user['userId'];
    return this.postService.update(postID, userId, updatePostDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Delete('delete/:id')
  delete(@Param('id', ParseIntPipe) postID: number, @Req() request: Request) {
    const userId = request.user['userId'];
    return this.postService.delete(postID, userId);
  }
}
