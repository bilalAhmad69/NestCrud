import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateBookmarkDto, EditBookmarkDto } from './dto';

@Injectable()
export class BookmarkService {
constructor(private prisma: PrismaService){}

getBookmarks(userId:number){
    return  this.prisma.bookmark.findMany({where:{userId:userId}});
}

getBookmarkById(userId:number , bookmarkId:number){
    return this.prisma.bookmark.findUnique({where:{id:bookmarkId , userId}});
}

async createBookmark(userId:number , dto:CreateBookmarkDto ){
    const bookmark = await this.prisma.bookmark.create({
      data:{
        userId,
        ...dto
      }
    });
    return bookmark;
}

async editBookmarkById(userId:number , bookmarkId:number, dto:EditBookmarkDto){
    const bookmark  =  await this.prisma.bookmark.findUnique({where:{id:bookmarkId}});
    if(!bookmark || bookmark.userId != userId){
        throw new  ForbiddenException(
            'Access to resources denied'
        )
    }
     return await this.prisma.bookmark.update({
    data:{
        ...dto
    },
    where:{
        id:bookmarkId,
    }
})
}

async deleteBookmarkById(userId:number , bookmarkId:number){
    const bookmark  =  await this.prisma.bookmark.findUnique({where:{id:bookmarkId}});
    if(!bookmark || bookmark.userId != userId){
        throw new  ForbiddenException(
            'Access to resources denied'
        )
    }
    await this.prisma.bookmark.delete({
        where:{id:bookmarkId}
    })
}
}
