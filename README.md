# dsd-ghidra
Ghidra loader and scripts for DS decompilation projects, powered by [`dsd`](https://github.com/AetiasHax/ds-decomp).

## Contents
- [Installation](#installation)
- [Usage](#usage)
- [How to build (Windows + IntelliJ)](#how-to-build-windows--intellij)
- [How to build (Linux + Eclipse)](#how-to-build-linux--eclipse)

## Installation
1. [Download the latest release](https://github.com/AetiasHax/dsd-ghidra/releases/latest)
2. In Ghidra, open the "File" menu and select "Install Extensions"
3. Click the <kbd>+</kbd> icon in the top-right and select the downloaded file
4. Press <kbd>OK</kbd> in the "Install Extensions" window
5. Restart Ghidra

## Usage

### Load a DS game
You can load a DS game by dropping a DS ROM file into the Ghidra project window, then following the steps as they appear.

> [!CAUTION]
> You may be prompted to auto-analyze your newly generated Ghidra program. Do not do this if you are going to use dsd! Instead, you should use the [sync script](#sync-with-dsd) since it will result in more accurate function analysis.

### Sync with dsd
You can synchronize your Ghidra program with a dsd configuration by running the `SyncDsd.java` script in the Script Manager. The script can also be added to the toolbar by checking the "In Tool" checkbox.

## How to build (Windows + IntelliJ)

1. Build the `build.ps1` PowerShell script to build the native Rust library.
2. Configure Gradle:
    1. Copy the `dsd-ghidra/gradle.properties.example` file to `dsd-ghidra/gradle.properties`.
    2. Edit the `GHIDRA_INSTALL_DIR` property in `gradle.properties` to point to your Ghidra installation.
3. Create the IntelliJ project:
    1. In IntelliJ, open `dsd-ghidra/build.gradle` as a new Gradle project.
4. Build the extension:
    1. In the Gradle tool window, run the `ghidra/distributeExtension` task.
    2. Now you should have a .zip file in `dsd-ghidra/dist/`

You can also debug the extension through IntelliJ:
1. Add all of Ghidra's JARs to your classpath. They can be located in `${GHIDRA_INSTALL_DIR}/Ghidra/` and its subdirectories.
2. Add an `Application` run configuration:
    1. Click "Modify options" and enable "Add VM options"
    2. Module: `dsd-ghidra.main`
    3. VM options: `-Djava.system.class.loader=ghidra.GhidraClassLoader`
    4. Main class: `ghidra.Ghidra`
    5. Program arguments: `ghidra.GhidraRun`
    6. Environment variables: `GHIDRA_INSTALL_DIR=C:/path/to/ghidra_11.2.1_PUBLIC/`

## How to build (Linux + Eclipse)

1. Run the `build.sh` bash script
    1. You can add the `--debug` flag to build debug versions
2. Configure Gradle:
    1. Copy the `dsd-ghidra/gradle.properties.example` file to `dsd-ghidra/gradle.properties`
    2. Edit the `GHIDRA_INSTALL_DIR` property in `gradle.properties` to point to your Ghidra installation
3. Load the project into Eclipse
    1. Ensure you have the latest version of GhidraDev installed
    2. Import the `dsd-ghidra` sub-project as a Gradle project
    3. GhidraDev -> Link Ghidra
    4. GhidraDev -> Export -> Extension