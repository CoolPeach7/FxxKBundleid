# IOS+OSX逆向去除应用Bundleid校验

在 iOS 设备上安装多个同一个 App 的方式只有一种，修改 *Info.plist* 中的 `CFBundleIdentifier` 。

> 在整个 iOS 生态中，Bundle Identifier 是作为一个 App 的唯一标识符存在。
>
>
> 对于拥有相同的 Bundle Identifier 的 App，无论 Binary 和资源文件都多大的差异，iOS 都会将它们视为同一个 App。
>
> 对于拥有不同的 Bundle Identifier 的 App，也无论 Binary 与和资源文件是否一致，iOS 会将它们视为不同 App。
>

而 *Info.plist* 文件，是整个 App 的信息、配置、权限的信息整合文件，其在 App 中起到至关重要的作用。

为了防止 *Info.plist* 被恶意篡改，iOS 提供一种数字签名技术。通过该技术，计算出 *Info.plist* 文件的 Hash 值，加密后存入到签名文件中。在安装时与安装后，可通过该签名文件存的 Hash 值进行文件签名校验。也因此，App 签名后无法修改 *Info.plist* 文件；而即使是已安装 App 的 *Info.plist* 文件，修改后也会导致 App 闪退。

所以可以得出结论，**对于已安装的 App 的 Info.plist 文件的 CFBundleIdentifier 值不会被修改**

通过上述结论，由于 *Info.plist* 文件的不可修改性质，我们可以在 App 运行时来读取 Info.plist 文件中的值来判断该值是否与出产时候相同，从而判断当前进程是否是一个多开 App。

`Foundation.framework` 提供了几种获取 App 的 Bundle Identifier 方法，基本如下：

```objectivec
NSBundle.mainBundle.bundleIdentifier;
[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleIdentifier"];
NSBundle.mainBundle.infoDictionary[@"CFBundleIdentifier"];
[NSDictioanry dictionaryWithContentsOfFile:@"Info.plist"][@"CFBundleIdentifier"]

```

使用上面几种的任意一种，就可以获取到当前 App 的 Bundle Identifier 值，之后通过 `-[NSString isEqualToString:]` 方法来判断是否分身。

# 1.重签名

苹果钥匙串访问获取证书


对QQ进行解包

![Untitled](https://cdn.staticaly.com/gh/loplopuu23/blog-image@master/20221101/Untitled-1.547gvcnx70c0.webp)

主要修改Info.plst文件,修改BundleIdentifier为任意值，并且修改qq.app为uu.app 在Info.plst修改对应值

![Untitled](https://cdn.staticaly.com/gh/loplopuu23/blog-image@master/20221101/Untitled-2.224oph2egmao.webp)

```jsx
codesign -f -s "iPhone Developer: xxxxx" uu.app --重签名
```

![Untitled](https://cdn.staticaly.com/gh/loplopuu23/blog-image@master/20221101/Untitled-3.6ys2yx0rfd00.webp)

登录后提示AppID验证失败，QQ做了Bundleid的校验 如果校验不对会登录失败

# 2.Hook

## 如何反检测多开

在已经知道如何检测多开的时候，就可以知道如何防止 App 检测多开了。

简单的来说，就是干掉上面的几个方法，强制返回一个原来的值即可。

### 检测不到多开

具体思路是判断返回值是不是真实的 Bundle Identifier，如果是则返回原来的 Bundle Identifier。这样做的目的防止影响到别的对象以及别的 key 对应的值。

## 3.**可能用到的工具**

1. [Theos](https://github.com/theos/theos)
2. [optool](https://github.com/alexzielenski/optool)/[insert_dylib](https://github.com/Tyilo/insert_dylib)
3. [unsign](https://github.com/steakknife/unsign) (optional)

```objectivec
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
```

> 在 App 运行时，除微信主二进制文件外，随着被加载到内存中的二进制还有：微信内置 Framework，微信所用到的系统 Framework，插件自身 dylib。而我们并不能保证系统 Framework 是否会调用、何时会调用 NSBundle 相关方法。如果系统 Framework 调用了相关方法，得到了假的 Bundle ID，则有可能出现无法预计的问题，甚至是出现了也找不到问题的bug。所以我们必须保证如果是系统调用的方法，要返回真实的 Bundle ID。同时，如果插件自身想要获取 Bundle ID，也应该要返回一个真实的 Bundle ID。于是提出需求：**如果是微信调用的方法，返回假值，否则返回真值。**我们可以通过 dyld 的 `dladdr()` 函数配合当前调用栈地址来判断**调用者**来自哪个二进制文件
>

![Untitled](https://cdn.staticaly.com/gh/loplopuu23/blog-image@master/20221101/Untitled-4.6jiniqwkqdk0.webp)

将以上代码保存为一个 Tweak.xm 文件(名字后缀名随意)，放在与uu.app 同级目录下，便于后续操作。

```bash
然后我们使用 Theos 的语法分析来把 Logos 转换成普通代码

logos.pl Tweak.xm > abc.mm
注意 abc 应该有 mm 作为后缀名，用于告诉 clang 目标语言类型

使用 clang 编译转换后的普通代码，并将结果放到 app 包内
clang -shared -undefined dynamic_lookup -o ./uu.app/Contents/MacOS/lib.dylib ./abc.mm
使用 optool/insert_dylib 往 uu 的 MachO 头部添加我们刚刚编译的 lib.dylib
./optool install -c load -p @executable_path/lib.dylib -t ./uu.app/Contents/MacOS/uu

如果你的 Mac app 没有签名的话，此时应该已经达成我们的需求了。但是实践中我们肯定不是对自己导出的未签名 Mac app 下黑手。所以需要去掉这个签名或重签名。因为笔者没有钱买开发者账号，故不知道如何重签名。

使用 codesign 去除签名
codesign -f -s "iPhone Developer: xxxxxx" uu.app
```
