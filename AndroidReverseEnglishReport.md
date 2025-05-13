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
>
>- Time: 2 days

## 2. Static Analysis

### 2.1 Tools installation

- Jadx: `brew install jadx`

### 2.2 Download target apk

- `git clone git@github.com:dineshshetty/Android-InsecureBankv2.git`

### 2.3 Sequence of login

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250510150653579.png" alt="image-20250510150653579" style="zoom:75%;" />



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

    <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250510115652196.png" alt="image-20250510115652196" style="zoom:33%;" />

  - Using `SharedPreferences` for storing credentials in an insecure manner (passwords use AES encryption with hardcoded key).

  - Logging usernames and passwords with `android.util.Log` (easily exposed).

  - **Recommendations**:
    - Do not store credentials locally.
    - Use Android Keystore and AES-GCM.
    - Use HTTPS for secure communication.

### 2.5 Change Password Vulnerability

- No validation of the current password when changing the password.
- New password sent via SMS, easily intercepted.
- Password transmitted in plaintext, should be hashed which is not reversible. Shouldn't use crypto, because crypto value could be decrypted.

## 3. Dynamic Analysis

>The InsecureBank APK version is too old, so it couldn't be installed on Android Studio. Therefore, I installed cmdline-tools and used the `sdkmanager` command line to create an Android emulator with a lower API version (API 22). However, it still failed because the Apple M4 chip does not support Frida. Fortunately, the app itself uses the HTTP protocol. (In the future, I will use other APKs to study HTTPS bypass techniques.)

### 3.1 Emulator Setup

- Install ARM64-compatible Android 6.0 system image:

  ```
  sdkmanager "system-images;android-23;google_apis;arm64-v8a"
  ```

- Create and launch an emulator:

  ```
  avdmanager create avd -n insecurebank_api23_arm64 -k "system-images;android-23;google_apis;arm64-v8a" --device "pixel" --force
  ```
  
- Start Emulator (use `adb devices` check weather emulator started)

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

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250510235320008.png" alt="image-20250510235320008" style="zoom: 25%;" />

### 3.4 Frida Installation Issues

- Due to Apple M4 chip compatibility issues, Frida installation failed. Used proxy for interception. And found that InsecureBank use HTTP so don't need frida anymore
- <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511114543408.png" alt="image-20250511114543408" style="zoom:33%;" />

### 3.5 API Testing and Findings

- Burp configuration 

  <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511125014064.png" alt="image-20250511125014064" style="zoom:33%;" />



- Emulator proxy configuration 

  ```
  adb shell settings put global http_proxy 172.32.249.143:8080
  ```

-  **Attention**！Previously, the proxy address was configured as 10.0.2.2:8888, which led to many detours. In fact, Burp should listen on this address, and the emulator should be configured to use this address as the proxy. Do not set it to 10.0.2.2, otherwise, Burp will not forward requests from the local machine to Flask.

- Setup server ip port at insecureBank APP:

  <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511195645954.png" alt="image-20250511195645954" style="zoom: 25%;" />

- start backend server:

  ```
  cd /Users/keeplook4ever/Desktop/Task/Android-InsecureBankv2-master/AndroLabServer
  conda activate
  pip install -r requirements.txt
  python app.py
  ```

- error, install py27 env:

  ```
  CONDA_SUBDIR=osx-64 conda create -n py27 python=2.7
  CONDA_SUBDIR=osx-64 conda activate py27
  pip install -r requirements.txt
  python app.py
  ```

  <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511121000801.png" alt="image-20250511121000801" style="zoom:25%;" />

### 3.6 Login Traffic Capture

- username + password:  eer/xxxx

  <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511125227948.png" alt="image-20250511125227948" style="zoom:25%;" />

- <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511125336137.png" alt="image-20250511125336137" style="zoom:25%;" />

- Since the `devadmin` username was discovered during static code review, I tried logging in with this username to see if it's a backdoor: It successfully logged in without any issue.

​	<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511125944852.png" alt="image-20250511125944852" style="zoom:25%;" />

​	<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511130050561.png" alt="image-20250511130050561" style="zoom:25%;" />

- Further verification: The password check should not exist. I tried changing the password to: devadmin/xxx999, and as expected, I was able to log in successfully, confirming that the `devadmin` account is a developer/test account with no password check.

  <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511130214542.png" alt="image-20250511130214542" style="zoom:25%;" />

### 3.7 Transfer API Traffic Capture:

- **Discovery**: The previously static-reviewed `/getaccounts` API allows brute-forcing to guess platform user account credentials.

  <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511130709396.png" alt="image-20250511130709396" style="zoom:25%;" />

- **`dotransfer` API**: This API passes `username+password` to check user permissions, but if a hacker obtains any user's account and password, they can perform any transfer by setting `to_acc=hacker`. Since there's a backend error, it could not be tested.

​	<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511131012422.png" alt="image-20250511131012422" style="zoom:25%;" />

### 3.8 viewstatement ：

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511131357028.png" alt="image-20250511131357028" style="zoom: 25%;" />

### 3.9 Test `changepasswd` API:

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511131444477.png" alt="image-20250511131444477" style="zoom: 25%;" />

​	<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511131646399.png" alt="image-20250511131646399" style="zoom:33%;" />

- **Interception and Replay**:

  <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511143356873.png" alt="image-20250511143356873" style="zoom:50%;" />

- **Replayed Successfully**: As shown, the request replayed successfully (response code: 200, message: Error, which is a backend error and can be ignored). This allows changing any existing user's password, a serious vulnerability.

  ![image-20250511143518065](/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511143518065.png)

### 3.10 Rebuilt SDK for Admin Access

> In static code analysis, I found that "button_CreateUser" is displayed only when `"R.string.is_admin"` is set to "yes". I attempted to bypass this by modifying the code:

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511140719372.png" alt="image-20250511140719372" style="zoom: 25%;" />

- Install APKTool:

  ```
  brew install apktool
  ```

- Decompile APK:

  ```
  apktool d ~/Desktop/Task/Android-InsecureBankv2-master/InsecureBankv2.apk -o insecurebank_dec
  ```

- Modify `res/values/strings.xml` to set `is_admin` to "yes":

- Rebuild and sign the APK:

  ```
  apktool b InsecureBank_decoded -o InsecureBankv2_admin.apk
  apksigner sign --ks debug.keystore --ks-key-alias androiddebugkey --ks-pass pass:android InsecureBankv2_admin.apk
  ```

  - Since `apksigner` was not found, I used the command `find ~/Library/Android/sdk/build-tools -name apksigner` to locate the `apksigner` tool:

    ```
    /Users/keeplook4ever/Library/Android/sdk/build-tools/35.0.1/apksigner
    /Users/keeplook4ever/Library/Android/sdk/build-tools/36.0.0/apksigner
    
    ```

  - Then used the absolute path to sign:

    ```
    /Users/keeplook4ever/Library/Android/sdk/build-tools/35.0.1/apksigner sign \
      --ks debug.keystore \
      --ks-key-alias androiddebugkey \
      --ks-pass pass:android \
      InsecureBankv2_admin.apk
    ```

- Generate a new `debug.keystore` if it is missing:

  ```
  keytool -genkey -v -keystore debug.keystore \
    -storepass android -alias androiddebugkey \
    -keypass android -keyalg RSA -keysize 2048 -validity 10000
  ```

- Install the signed APK on the emulator:

  ```
  adb install -r InsecureBankv2_admin.apk
  ```

  If there was an error, uninstall the previous APK and reinstall:

  ```
  adb uninstall com.android.insecurebankv2
  ```

  

- Successfully displayed the "Create User" button: Although the backend doesn't implement the functionality, this proves that the modified APK allows creating any account (a critical vulnerability, as only admins should have this access).

  <img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511143727567.png" alt="image-20250511143727567" style="zoom:30%;" />

## 4. **Bonus for Credentials and Access Control**

### 4.1. **Direct Exposure of Backend Database Address and Tables**

The application defines a custom `ContentProvider` for tracking user information but does not set access control, allowing any app to query or tamper with the content. Testers can retrieve, delete, or forge user records via the `content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers` URI. Additionally, database fields are stored in plaintext without access control or audit logs. It is recommended to restrict export permissions and encrypt sensitive fields.

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511175825869.png" alt="image-20250511175825869" style="zoom:30%;" />



The code directly exposes the backend server database address and table names, making it easy to leak data. You can directly query users with adb, for example, finding users `jack` and `devadmin`:

```

adb shell content query --uri content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers
```

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511180433223.png" alt="image-20250511180433223" style="zoom:50%;" />



### 4.2. **Login Brute-Force, No Session/Token Used in Login Records**

For example, using `jack`'s username, brute-force password payloads can be constructed:

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511145236954.png" alt="image-20250511145236954" style="zoom:35%;" />

The result of the attack allows filtering out successful passwords by comparing response lengths.

**Fix Recommendation**: Limit the number of login attempts for the same device. For example, after 3 failed attempts within 5 minutes, prompt for CAPTCHA or block the current device/IP from attempting further logins. Account lockout should be avoided as it could lock normal user accounts when hackers attempt brute-forcing.

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511145408504.png" alt="image-20250511145408504" style="zoom: 25%;" />



### 4.3. **Transfer API Not Verified, Source Account Not Checked**

Input: `from account: admin`, `to account: jack`, current logged-in user is `jack` with account number `555555555`, and `admin` has account `999999999`.

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511150144495.png" alt="image-20250511150144495" style="zoom: 25%;" />



Tested the `transfer` API and successfully transferred funds.

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511145948706.png" alt="image-20250511145948706" style="zoom:25%;" />



This allowed unauthorized transfers, and funds could be transferred from all accounts to `jack` by exploiting the vulnerability. Testing with 10000 over 20 accounts:

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511150837892.png" alt="image-20250511150837892" style="zoom: 25%;" />



<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511150955424.png" alt="image-20250511150955424" style="zoom: 25%;" />

Only `999999999` was successful, indicating other account IDs did not exist in the payload. More attempts were not made due to time constraints.

### 4.4. **Password Encryption Key Hardcoded, Local Storage and Logging**

<img src="/Users/keeplook4ever/Library/Application Support/typora-user-images/image-20250511152116620.png" alt="image-20250511152116620" style="zoom: 25%;" />



**Code Issues**:

- Hardcoded key, easy to reverse-engineer and leak, effectively like plaintext transmission.
- Static zero Initialization Vector (IV) in CBC mode leads to password leaks: identical plaintext passwords will always generate the same ciphertext.
- Unsafe AES mode: CBC, while strong, does not guarantee data integrity. AES-GCM should be used.

Example code to upgrade to AES-GCM with random IV:

```java

SecureRandom random = new SecureRandom();
byte[] iv = new byte[12]; // GCM recommends 12-byte IV
random.nextBytes(iv);

SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

byte[] cipherText = cipher.doFinal(plainText.getBytes());
```



### 4.5. **Misconfigured AndroidManifest.xml**

1. `android:debuggable="true"` opens debug mode, allowing any USB debugging tool (adb shell, frida, re-framework) to attach.
    It should be changed to `android:debuggable="false"` or removed.

2. `android:allowBackup="true"` enables attackers to extract data via `adb backup`, which should be set to `android:allowBackup="false"`.

3. Multiple components exposed directly:

   ```shell
   
   <activity android:name="...DoTransfer" android:exported="true"/>
   <activity android:name="...ViewStatement" android:exported="true"/>
   <activity android:name="...PostLogin" android:exported="true"/>
   <activity android:name="...ChangePassword" android:exported="true"/>
   <receiver android:name="...MyBroadCastReceiver" android:exported="true"/>
   <provider android:name="...TrackUserContentProvider" android:exported="true"/>
   ```

   

   Any app can directly send Intent to these activities, potentially bypassing authentication and accessing sensitive pages.

   The exposed `Provider` allows third parties to read and write the `trackerusers` database.

   The exposed `Receiver` can be misused to trigger internal operations (e.g., broadcast injection).

​	**Recommendation**: Set `android:exported="false"` or add `android:permission` to restrict access.

------

## 5. To Be Continued

- Research on high version Android and APKs in the Android market.

- Study on HTTPS bypass and Frida.

- Further research on ADB usage.

