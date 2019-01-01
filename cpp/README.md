# Setup project


## Steps

* Download [gn](https://gn.googlesource.com/gn/) and put gn into $PATH
* Follow [standalone gn](https://gn.googlesource.com/gn/+/master/docs/standalone.md) to copy minimal required
files to use gn.
* Run gn and build:
    gn gen out
    ninja -C out <target>
