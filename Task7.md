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
> and then connect using the IP `10.0.2.2` on port `8065`, since `10.0.2.2` is Android Studio's loopback address basically

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

If we scroll down a bit, we find the underlying code that writes the downloaded files to disk

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

