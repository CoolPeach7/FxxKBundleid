%config(generator=internal)
#include <dlfcn.h>
// You don't need to #include <substrate.h>, it will be done automatically, as will
// the generation of a class list and an automatic constructor.
#import <Foundation/Foundation.h>
// 以 - (NSString *)bundleIdentifier 为例

%hook NSBundle
- (NSString *)bundleIdentifier{
    NSString *str =  @"com.tencent.qq";
    NSArray *address = [NSThread callStackReturnAddresses];


    NSDictionary *dic = [[NSBundle mainBundle]infoDictionary];
    [dic setValue:@"com.tencent.qq" forKey:@"CFBundleIdentifier"];

    Dl_info info = {0};
    if(dladdr((void *)[address[2] longLongValue], &info) == 0) return %orig;
    NSString *path = [NSString stringWithUTF8String:info.dli_fname];
    if ([path hasPrefix:NSBundle.mainBundle.bundlePath]) {
    		NSLog(@"!!!!!!!!!!!!!");
            return str;
    } else {
        //  二进制是系统或者越狱插件
    		NSLog(@"!!!!!!系统!!!!!!");
        	return %orig;
    }
}
%end
