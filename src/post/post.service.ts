import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreatePostDto } from './dto/createPostDto';
import { PrismaService } from 'src/prisma/prisma.service';
import { UpdatePostDto } from './dto/updatePostDto';

@Injectable()
export class PostService {
  constructor(private readonly prismaService: PrismaService) {}

  getAll() {
    return this.prismaService.post.findMany({
      include: {
        user: {
          select: {
            username: true,
            email: true,
            password: false,
          },
        },
        comments: {
          include: {
            user: {
              select: {
                username: true,
                email: true,
                password: false,
              },
            },
          },
        },
      },
    });
  }

  async create(createPostDto: CreatePostDto, userId: any) {
    const { title, body } = createPostDto;
    await this.prismaService.post.create({ data: { title, body, userId } });
    return { data: 'Post created!' };
  }

  async update(postID: number, userId: any, updatePostDto: UpdatePostDto) {
    const post = await this.prismaService.post.findUnique({
      where: { postID },
    });
    if (!post) throw new NotFoundException('Post not found');

    if (post.userId !== userId)
      throw new ForbiddenException('Forbidden action');
    await this.prismaService.post.update({
        where: { postID },
        data: { ...updatePostDto },
      });
    return { data: 'Post updated successfully' };
  }

  async delete(postID: number, userId: number) {
    const post = await this.prismaService.post.findUnique({
      where: { postID },
    });
    if (!post) throw new NotFoundException('Post not found');

    if (post.userId !== userId)
      throw new ForbiddenException('Forbidden action');
    await this.prismaService.post.delete({ where: { postID } });
    return { data: 'Post deleted' };
  }
}
