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

  /**
   * Récupère tous les posts avec les utilisateurs et les commentaires associés.
   */
  async getAll() {
    return this.prismaService.post.findMany({
      include: {
        user: {
          select: {
            username: true,
            email: true,
          },
        },
        comments: {
          include: {
            user: {
              select: {
                username: true,
                email: true,
              },
            },
          },
        },
      },
    });
  }

  /**
   * Crée un nouveau post pour l'utilisateur spécifié.
   */
  async create(createPostDto: CreatePostDto, userId: number) {
    const { title, body } = createPostDto;
    await this.prismaService.post.create({
      data: { title, body, userId },
    });
    return { data: 'Post created!' };
  }

  /**
   * Met à jour un post existant si l'utilisateur a l'autorisation.
   */
  async update(postID: number, userId: number, updatePostDto: UpdatePostDto) {
    const post = await this.validatePostAndUser(postID, userId);
    await this.prismaService.post.update({
      where: { postID },
      data: { ...updatePostDto },
    });
    return { data: 'Post updated successfully' };
  }

  /**
   * Supprime un post existant si l'utilisateur a l'autorisation.
   */
  async delete(postID: number, userId: number) {
    const post = await this.validatePostAndUser(postID, userId);
    await this.prismaService.post.delete({ where: { postID } });
    return { data: 'Post deleted' };
  }

  /**
   * Valide l'existence du post et les permissions de l'utilisateur.
   */
  private async validatePostAndUser(postID: number, userId: number) {
    const post = await this.prismaService.post.findUnique({
      where: { postID },
    });
    if (!post) {
      throw new NotFoundException('Post not found');
    }
    if (post.userId !== userId) {
      throw new ForbiddenException('Forbidden action');
    }
    return post;
  }
}
