# Android-InsecureBankv2 Reverse Analysis Report

## 1. Preface

>
>
>This project serves as both a home task for an interview and an opportunity for learning Android reverse engineering. The analysis includes static and dynamic analysis of the Android application "InsecureBankv2" hosted on GitHub.
>
>- Task:
>
> <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511154925699.png" alt="image-20250511154925699" style="zoom:33%;" />
>
>-  Target: https://github.com/dineshshetty/Android-InsecureBankv2
>
>-  Tools:
>   -  chatgpt !!!
>   -  apktool
>   -  jadx
>   -  Android Studio
>   -  BurpSuite
>   -  OS: Apple M4 (Macbook Air)
>   -  Cmdline tool: iTerm + oh-my-zsh !!!
>-  Process:
>   -  decide target : Android + InsecureBank
>   -  Static Analysis: jadx + chatgpt
>   -  Dynamic Analysis: adb + apktool + BurpSuite
>   -  Bonus summary 
>   -  create GitHub repository and upload
>-  Time: 2 days

## 2. Static Analysis

### 2.1 Tools installation

- Jadx: `brew install jadx`

### 2.2 Download target apk

- `git clone git@github.com:dineshshetty/Android-InsecureBankv2.git`

### 2.3 Sequence of login

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250510150653579.png" alt="image-20250510150653579" style="zoom: 50%;" />



- new user: createUser

- oldUser: filldata from local -> perform login -> check if success

  - Success -> save Creds(user, pass) ->PostLogin -> (doTransfer / viewStatement / changePassword)

    - api: http://ip:port/dotransfer
      - Post
      - username+password+from_acc+to_acc+amount
    - api: http://ip:port/getaccounts
      - Post
  
      - username + password
  
    - api: http://ip:port/changepassword
      - Post
      - username + new password
  
  - Fail -> WrongLogin -> login

### 2.4 Login Action

 - API: 
   - http://ip:port/login 
     - post
     - username + password
   - http://ip:port/devlogin
     - post
     - username + password

- **Problems**:

  - Using HTTP, easy to be intercepted by man-in-the-middle (should use HTTPS).

    ![image-20250510115652196](/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250510115652196.png)

  - SharedPreferences 存储⽤户名密码，安全性很低。（user只做了base64编码，password做了aes对称

    加密，⽽且密钥硬编码了(Hardcoded Key)

    	- String key = "This is the super secret key 123";

  - 使⽤android.util.Log 打印登录⽤户名密码信息，容易被⿊客获取

  - 改进措施：

    - 尽量不要本地存储⽤户密码
    - 不能⽤android.util.Log 打印登录⽤户秘密码信息造成信息泄露，可记录脱敏后的username信息
    - 即使存储密码，也建议使⽤** Android Keystore + AES-GCM

    - 使⽤https 加密传输

### 2.5 Change Password Vulnerability

- 没有验证是否本⼈发起的请求，⽐如验证当前⽤户的账号密码 或 ⼿机号⼆次验证账号本⼈所有，直接发起了

  新密码的设置，容易被⿊客直接更改正常⽤户的密码

- 新密码直接通过sms发送到了本⼈⼿机号，容易被窃听造成密码泄漏

- 新密码是明⽂传输的，容易被中间⼈攻击获取，应该做哈希处理，传输哈希值并存储哈希值。（数据库不应该

​	存储明⽂密码，应存储密码哈希以防⽌数据库被攻击后密码泄漏，加密存储也不推荐，因为加密值可以被解

​	密）

## 3. Dynamic Analysis

>InsecureBank apk版本太老，导致android studio 装不上，于是安装cmdline-tools， 使用sdkmanager 命令行创建低版本API22 的android模拟器。结果还是失败，因为apple M4芯片不能支持 Frida。好在此app本身就是http协议。**（后续会利用其他apk研究https的相关绕过）**

### 3.1 **Emulator Setup**

- Install ARM64-compatible Android 6.0 system image:

  ```
  sdkmanager "system-images;android-23;google_apis;arm64-v8a"
  ```

- Create and launch an emulator:

  ```
  avdmanager create avd -n insecurebank_api23_arm64 -k "system-images;android-23;google_apis;arm64-v8a" --device "pixel" --force
  ```
  
- 启动模拟器（用`adb devices`列出当前模拟器）

  ```
  emulator -avd insecurebank_api23_arm64
  ```
  
  

### 3.2 Install InsecureBankv2.apk in Emulator

``` 
adb install ~/Desktop/Task/Android-InsecureBankv2-master/InsecureBankv2.apk
```

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511115236645.png" alt="image-20250511115236645" style="zoom:25%;" />

### 3.3 Burp Suite Configuration

- Install Burp certificate to the emulator:

```
adb root
adb remount
adb push burp_cert.der /sdcard/
```

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250510235320008.png" alt="image-20250510235320008" style="zoom:25%;" />

### 3.4 Frida Installation Issues

- Due to Apple M4 chip compatibility issues, Frida installation failed. Used proxy for interception. And found that InsecureBank use HTTP so don't need frida anymore
- <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511114543408.png" alt="image-20250511114543408" style="zoom: 33%;" />

### 3.5 API拦截测试

- Burp配置

  <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511125014064.png" alt="image-20250511125014064" style="zoom:25%;" />



- 模拟器配置代理：

  ```
  adb shell settings put global http_proxy 172.32.249.143:8080
  ```

- app中设置后端地址

  <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511195645954.png" alt="image-20250511195645954" style="zoom:30%;" />

-  **这里之前配置代理地址为10.0.2.2:8888, 走了很多弯路，实际上burp监听此地址，模拟器配置代理这个地址就可以。不要配置为10.0.2.2，否则burp将到本机的请求不会转发到flask.**

- 开启后台

  ```
  cd /Users/keeplook4ever/Desktop/Task/Android-InsecureBankv2-master/AndroLabServer
  conda activate
  pip install -r requirements.txt
  python app.py
  ```

- 报错，重新安装python27环境

  ```
  CONDA_SUBDIR=osx-64 conda create -n py27 python=2.7
  CONDA_SUBDIR=osx-64 conda activate py27
  pip install -r requirements.txt
  python app.py
  ```

  <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511121000801.png" alt="image-20250511121000801" style="zoom:30%;" />

### 3.6 开始抓包测试

- App 中输⼊⽤户名密码：eer/xxxx

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511125227948.png" alt="image-20250511125227948" style="zoom:33%;" />

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511125336137.png" alt="image-20250511125336137" style="zoom:33%;" />

- 因为之前代码审计发现devadmin 用户名，于是用此用户名登录看看效果：是否是后门：果然是直接登录成功

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511125944852.png" alt="image-20250511125944852" style="zoom:25%;" />

![image-20250511130050561](/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511130050561.png)



- 再次验证应该是不校验密码的，更改密码试试：devadmin/xxx999, 果然登录成功，验证了devadmin账号为开发测试账号直接登录后台无校验。

![image-20250511130214542](/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511130214542.png)

- Transfer接口抓包：

发现之前静态审计中的 /getaccounts接口。此接口可根据暴力破解来猜测获取平台注册用户账号密码。

![image-20250511130709396](/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511130709396.png)

- dotransfer接口：这块是传递的username+password判断用户权限，但如果黑客拿到任一用户的账号密码，就可以直接设置任意转账给黑客，只需要to_acc=hacker 就可以了。由于后台实现error因此无法测试。

![image-20250511131012422](/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511131012422.png)

- viewstatement ：

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511131357028.png" alt="image-20250511131357028" style="zoom:25%;" />

- 测试 changepasswd 

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511131444477.png" alt="image-20250511131444477" style="zoom:25%;" />

![image-20250511131646399](/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511131646399.png)



- 对此请求进行拦截，并改包重放：

![image-20250511143356873](/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511143356873.png)

- 如下图，可正常重放(response code;200, message: Error是后台错误忽略) 此处可更改任意存在用户的密码，极其严重漏洞。

![image-20250511143518065](/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511143518065.png)

### 3.7. rebuit sdk for admin

>
>
>在静态代码分析中看到“button_CreateUser"的显示鉴权: 只有"R.string.is_admin"才会显示。尝试进行break:

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511140719372.png" alt="image-20250511140719372" style="zoom:33%;" />

1. 安装apktool

   ```
   brew install apktool
   ```

2. 反编译apk:

   ```shell
   apktool d ~/Desktop/Task/Android-InsecureBankv2-master/InsecureBankv2.apk -o insecurebank_dec
   ```


3. 更改res/values/strings.xml中的"is_admin" 为 "yes":

   ![image-20250511141257907](/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511141257907.png)

   4. 重新打包并签名

      ```shell
      apktool b InsecureBank_decoded -o InsecureBankv2_admin.apk
      apksigner sign --ks debug.keystore --ks-key-alias androiddebugkey --ks-pass pass:android InsecureBankv2_admin.apk
      ```

      其中apksigner没找到，于是用命令“find ~/Library/Android/sdk/build-tools -name apksigner" 找到 apksigner 命令位置：

      ```shell
      /Users/keeplook4ever/Library/Android/sdk/build-tools/35.0.1/apksigner
      /Users/keeplook4ever/Library/Android/sdk/build-tools/36.0.0/apksigner
      ```

      于是使用绝对路径来签名：

      ```shell
      /Users/keeplook4ever/Library/Android/sdk/build-tools/35.0.1/apksigner sign \
        --ks debug.keystore \
        --ks-key-alias androiddebugkey \
        --ks-pass pass:android \
        InsecureBankv2_admin.apk
      ```

      报错没有 `debug.keystore` 于是生成：

      ```shell
      keytool -genkey -v -keystore debug.keystore \
        -storepass android -alias androiddebugkey \
        -keypass android -keyalg RSA -keysize 2048 -validity 10000
      ```

      

5. 将打包签名后的apk包加载到模拟器中：

   ```shell
   adb install -r InsecureBankv2_admin.apk
   ```

   报错后卸载原来的apk重新安装：

   ```shell
   adb uninstall com.android.insecurebankv2
   
   ```

6. 可看到已经成功展示了"Create User"按钮：由于此接口后台未实现，但不影响证明利用此编译好的apk可以直接创建任意账号（越权，理论上只有admin才可以，极其严重漏洞）

   <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511143727567.png" alt="image-20250511143727567" style="zoom: 25%;" />









## 4. Bonus for credentials and access control

### 4.1. 直接暴露后台数据库地址和库表

应用定义了一个自定义 `ContentProvider` 用于追踪用户信息，但未设置访问权限，导致其内容可以被任意 App 查询、篡改。经测试，攻击者可通过 `content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers` URI 获取、删除或伪造用户记录。此外，数据库字段存在明文存储风险，未采用任何访问控制或日志审计，建议限制导出权限，并加密存储敏感字段。

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511175825869.png" alt="image-20250511175825869" style="zoom:25%;" />

以上代码直接暴露后台server数据库地址和库表名称，极容易造成数据泄露。可直接使用adb查询用户如下：发现用户jack+devadmin

```shell
adb shell content query --uri content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers
```

![image-20250511180433223](/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511180433223.png)

### 4.2. login 爆破，登录记录未使用sessionid/token标识。

以jack用户名为例，构造password payloads:

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511145236954.png" alt="image-20250511145236954" style="zoom: 33%;" />

发起攻击结果如下：可通过response length不同瞬间筛选出成功爆破的密码。

修复建议：对于同一设备登录尝试次数要有限制，比如登录失败3次在5分钟内，就可以弹出验证码或禁止当前设备/ip发起登录请求。不建议用账户锁定（当黑客爆破正常用户时，可能会使得正常用户的账号被锁定。）

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511145408504.png" alt="image-20250511145408504" style="zoom: 25%;" />

### 4.3. transfer没有做校验，当前转账的from是否是当前登录用户：

 输入：from account: admin, to account: jack，获取当前登录用户jack的账号：555555555，admin：999999999

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511150144495.png" alt="image-20250511150144495" style="zoom: 33%;" />

尝试transfer接口：发现转账成功。

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511145948706.png" alt="image-20250511145948706" style="zoom:25%;" />

这样可以直接便利所有账号，把每个账号的钱都转给jack，造成越权。用10000测试，测试20个账号：如下：

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511150837892.png" alt="image-20250511150837892" style="zoom: 33%;" />

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511150955424.png" alt="image-20250511150955424" style="zoom:33%;" />

发现只有999999999账号转成功了，说明此次payloads账号中其他uid不存在，由于时间限制不做更多尝试。

### 4.4. 密码加密密钥硬编码，且使用本地存储和日志

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511152116620.png" alt="image-20250511152116620" style="zoom:33%;" />

这块代码的问题：

- 密钥硬编码，容易被逆向破解泄露，相当于明文传输
- 静态，全零的Initialization Vector, 在CBC模式下，造成密码泄漏：相同密码明文总是生成相同密文。
- 不安全的AES模式：CBC虽然加密强，但无法保证数据完整性，应该使用AES-GCM 模式

这里是升级使用GCM和随机IV的代码示例：

```java
SecureRandom random = new SecureRandom();
byte[] iv = new byte[12]; // GCM 推荐 12 字节 IV
random.nextBytes(iv);

SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

byte[] cipherText = cipher.doFinal(plainText.getBytes());
```



### 4.5. AndroidManifest.xml 配置不当

1. `android:debuggable="true"` 调试模式打开，可被任意USB调试工具（adb shell, frida, re-framework) 附加

   应改为`android:debuggable="false"` 或者直接删除该配置

2. `android:allowBackup="true"` 开启则允许攻击者通过`adb backup`, 建议修改为`android:allowBackup="false"`

3. 多个组件直接对外暴露

   ```shell
   <activity android:name="...DoTransfer" android:exported="true"/>
   <activity android:name="...ViewStatement" android:exported="true"/>
   <activity android:name="...PostLogin" android:exported="true"/>
   <activity android:name="...ChangePassword" android:exported="true"/>
   <receiver android:name="...MyBroadCastReceiver" android:exported="true"/>
   <provider android:name="...TrackUserContentProvider" android:exported="true"/>
   ```

   任意 App 可直接发送 Intent 调用这些 Activity，可能绕过认证跳转到敏感页面

   暴露的 Provider 允许第三方读写数据库 `trackerusers`

   暴露的 Receiver 可能被滥用触发内部操作（如广播注入）

   建议：设置`android:exported="false"` 或添加`android:permission` 来限制访问

   

   

## 5. To Be Continued

#### 1. 高版本Android和android市场上apk 的研究（此次InsecureBank为demo学习版）

#### 2. Https 绕过和 Frida 等的研究

#### 3. 更多adb用法研究



