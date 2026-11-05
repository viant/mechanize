#import <AppKit/AppKit.h>

static NSString * const ownerType = @"com.viant.mechanize.private-clipboard-owner";
static NSPasteboard *privateBoard(const char *name) {
    return name && name[0] ? [NSPasteboard pasteboardWithName:[NSString stringWithUTF8String:name]] : [NSPasteboard generalPasteboard];
}
// Only the opaque owner marker and revision are ever read. No clipboard text
// getter, screenshot, log or agent serialization exists in this transport.
static BOOL ownsBoard(NSPasteboard *board, const char *token, long long revision) {
    if (!board || !token || board.changeCount != revision) return NO;
    NSData *expected = [[NSString stringWithUTF8String:token] dataUsingEncoding:NSUTF8StringEncoding];
    return [[board dataForType:ownerType] isEqualToData:expected] && board.changeCount == revision;
}
int mechanize_password_clipboard_stage(const char *name,const char *token,const void *bytes,size_t size,long long *revision) {
    @autoreleasepool { NSPasteboard *board=nil; @try {
        if (!token || !bytes || !size || !revision) return 0;
        board=privateBoard(name);
        *revision=[board prepareForNewContentsWithOptions:NSPasteboardContentsCurrentHostOnly];
        NSPasteboardItem *item=[[NSPasteboardItem alloc] init];
        NSMutableData *secret=[NSMutableData dataWithBytes:bytes length:size];
        BOOL staged=NO;
        @try {
            BOOL valid=[item setData:secret forType:NSPasteboardTypeString] &&
                [item setData:[[NSString stringWithUTF8String:token] dataUsingEncoding:NSUTF8StringEncoding] forType:ownerType] &&
                [item setData:[NSData data] forType:@"org.nspasteboard.ConcealedType"] &&
                [item setData:[NSData data] forType:@"org.nspasteboard.TransientType"];
            if (valid) staged=[board writeObjects:@[item]];
            *revision=board.changeCount;
        } @finally {
            [secret resetBytesInRange:NSMakeRange(0,secret.length)];
            [item release];
        }
        return staged && ownsBoard(board,token,*revision) ? 1 : 0;
    } @catch(NSException *exception) {
        // A write can precede an exception. Preserve its owned revision so
        // unconditional caller cleanup can still remove the staged secret.
        @try { if (revision && ownsBoard(board,token,board.changeCount)) *revision=board.changeCount; } @catch(NSException *ignored) {}
        return 0;
    } }
}
int mechanize_password_clipboard_owned(const char *name,const char *token,long long revision) {
    @autoreleasepool { @try { return ownsBoard(privateBoard(name),token,revision)?1:0; } @catch(NSException *exception){return 0;} }
}
int mechanize_password_clipboard_clear(const char *name,const char *token,long long revision) {
    @autoreleasepool { @try {
        NSPasteboard *board=privateBoard(name);
        if (!board || revision<0) return 0;
        if (board.changeCount!=revision) return 2; // Preserve a newer item.
        if (!ownsBoard(board,token,revision)) {
            // A failed stage may have left only our empty revision.
            return board.types.count==0 ? 1 : 0;
        }
        [board clearContents];
        return board.types.count==0 ? 1 : 0;
    } @catch(NSException *exception){return 0;} }
}
