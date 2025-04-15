# Angry Network Scanner 
<!-- <img src="img/banner.png" width="450" height="200" alt="AngryNetScan"> -->

**Local Network Scan**

![image](img/demo1.png)

**Real-time Network Packet Capture**

![image](img/demo2.png)

## Run (Pre-Compiled Jar)

```bash
java -jar AngryNetScan.jar
```

## Compile (Linux)
Make desired changes to AngryNetScan.java and run
```bash
javac -cp .:lib/* AngryNetScan.java
jar cvfm AngryNetScan.jar MANIFEST.MF AngryNetScan.class lib/*
java -jar AngryNetScan.jar
```

## Note
For Windows or Mac, replace libraries in `lib` folder with your OS specific versions and run compile command again and run the program.
