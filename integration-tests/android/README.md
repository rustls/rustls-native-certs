Android Instrumentation Tests
=============================

The project runs smoketest and compare_mozilla tests on a
Android Virtual Device (AVD) emulator or physical device.

Connect through adb shell to a AVD or physical device and
run the following command:

```bash
./gradlew test connectedAndroidTest
```