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

> I will note though that if you are using WSL like I am, I was running the Mattermost instance from WSL but running Android Studio from Windows. In order to have the app running on Windows connect to the Mattermost instance in WSL, use the below command to basically forward the port on WSL to your Windows machine
```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8065 connectaddress=172.30.48.197 connectport=8065
```
> and then connect using the IP `10.0.2.2` on port `8065`, since `10.0.2.2` is Anndroid Studio's loopback address basically

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

If we look deeper and look at the file `D3/j` (a lot of the function and class names that jadx-gui shows us are abstracted), we find what appears to be the underlying code that downloads files

```java
package D3;

import A.AbstractC0003b0;
import G3.B;
import T3.G;
import androidx.room.C;
import androidx.room.C0415b;
import androidx.room.L;
import com.badguy.mmarchiver.ui.screen.MainScreenKt;
import com.badguy.mmarchiver.ui.screen.MainScreenViewModel;
import com.badguy.mmarchiver.worker.ZipArchiver;
import g3.C0624F;
import h3.AbstractC0658a;
import h3.AbstractC0662e;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;
import k3.C0751i;
import kotlin.jvm.internal.E;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.ClassSerialDescriptorBuilder;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.internal.ObjectSerializer;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptorKt;
import kotlinx.serialization.internal.TripleSerializer;
import kotlinx.serialization.modules.SerializersModuleCollector;
import net.axolotl.zippier.ZipFormat;
import okhttp3.ResponseBody;
import okhttp3.internal.cache.DiskLruCache;
import org.slf4j.Logger;
import retrofit2.Response;
import u3.InterfaceC1174c;

/* loaded from: classes.dex */
public final /* synthetic */ class j implements InterfaceC1174c {

    /* renamed from: d, reason: collision with root package name */
    public final /* synthetic */ int f1104d;

    /* renamed from: e, reason: collision with root package name */
    public final /* synthetic */ Object f1105e;

    public /* synthetic */ j(int i, Object obj) {
        this.f1104d = i;
        this.f1105e = obj;
    }

    @Override // u3.InterfaceC1174c
    public final Object invoke(Object obj) {
        Response response;
        String valueOf;
        switch (this.f1104d) {
            case 0:
                return ((k) this.f1105e).c(((Integer) obj).intValue());
            case 1:
                String str = (String) this.f1105e;
                String it = (String) obj;
                kotlin.jvm.internal.r.e(it, "it");
                if (m.q0(it)) {
                    if (it.length() >= str.length()) {
                        return it;
                    }
                    return str;
                }
                return AbstractC0003b0.f(str, it);
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
            case 3:
                T3.u uVar = (T3.u) this.f1105e;
                G it3 = (G) obj;
                kotlin.jvm.internal.r.e(it3, "it");
                return uVar.onPathResult(it3, "listRecursively");
            case 4:
                Callable callable = (Callable) this.f1105e;
                kotlin.jvm.internal.r.e((V1.a) obj, "it");
                return callable.call();
            case 5:
                C c5 = (C) this.f1105e;
                W1.a db = (W1.a) obj;
                kotlin.jvm.internal.r.e(db, "db");
                c5.f6490g = db;
                return C0624F.f8096a;
            case 6:
                L l4 = (L) this.f1105e;
                C0415b config = (C0415b) obj;
                kotlin.jvm.internal.r.e(config, "config");
                return l4.createOpenHelper(config);
            case 7:
                return MainScreenKt.n((MainScreenViewModel) this.f1105e, ((Boolean) obj).booleanValue());
            case 8:
                return ZipArchiver.a((ZipArchiver) this.f1105e, (String) obj);
            case 9:
                if (obj == ((AbstractC0658a) this.f1105e)) {
                    return "(this Collection)";
                }
                return String.valueOf(obj);
            case 10:
                AbstractC0662e abstractC0662e = (AbstractC0662e) this.f1105e;
                Map.Entry it4 = (Map.Entry) obj;
                kotlin.jvm.internal.r.e(it4, "it");
                StringBuilder sb = new StringBuilder();
                Object key = it4.getKey();
                String str2 = "(this Map)";
                if (key == abstractC0662e) {
                    valueOf = "(this Map)";
                } else {
                    valueOf = String.valueOf(key);
                }
                sb.append(valueOf);
                sb.append('=');
                Object value = it4.getValue();
                if (value != abstractC0662e) {
                    str2 = String.valueOf(value);
                }
                sb.append(str2);
                return sb.toString();
            case 11:
                return ObjectSerializer.a((ObjectSerializer) this.f1105e, (ClassSerialDescriptorBuilder) obj);
            case 12:
                return PluginGeneratedSerialDescriptorKt.a((SerialDescriptor) this.f1105e, ((Integer) obj).intValue());
            case 13:
                return TripleSerializer.a((TripleSerializer) this.f1105e, (ClassSerialDescriptorBuilder) obj);
            case 14:
                return SerializersModuleCollector.a((KSerializer) this.f1105e, (List) obj);
            default:
                return DiskLruCache.b((DiskLruCache) this.f1105e, (IOException) obj);
        }
    }
}
```

Based on the name of the apk, `mmarchiver`, it seems pretty obvious that what this app does is download any media (basically any uploaded files) that are uploaded in Mattermost, and saves them to the Android phone. This is further backed up by the presence of a class named `FileSearchWorker`, which I won't show the disassembly of since it's not that important, but is pretty obviously used to find such uploaded files. 

Well, let's test this theory. Since in the constructor for `FileDownloadWorker` we saw a `zipArchiver` object get initialized, let's upload a zip file and see what happens

I create a file called `test.zip` which just contains a text file, named `hi.txt`, whose contents is literally just the word `hi`

Uploading it to the `Public` channel and then running the app (it prompts you to log in as a certain user when you do it the first time. I just used the credentials for `decimalpiglet81`)

Looking at the app logs, filtering by the word "format", we can see that it detected our zip file, and interestingly, appears to unzip it since it seems to detect the txt file within it

![image2](./images/task7img2.png)

Filtering by the word "zip" is even more telling

![image3](./images/task7img3.png)

We can see the path it saves the zip to, which is at `/data/user/0/com.badguy.mmarchiver/cache/download/test.zip`, but the extraction directory is at `/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/test`

From this, we can assume that `hi.txt` is at `/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/test/hi.txt` before it gets archived

Speaking of the archiving part, you can ignore the archive part. That's basically the app living up to its name and archiving the downloaded file, but for the purposes of the vulnerability research, that avenue doesn't lead anywhere

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

Essentially, it's done by having the inner zip be named something like `../exploited`. So for example, if the inner zip has a file like `inside.txt`, for our app, instead of it getting written to 

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

Ok, good work by the developers, it appears that ZipSlip, or at least the most common type, is blocked. Going back to jadx-gui, let's try to find where the logic is that checks this

At `Q3/a`, we can find the ZipSlip check

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

