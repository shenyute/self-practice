takescreenshot: takescreenshot.c
	  gcc -g `pkg-config --cflags libavformat libavcodec libavfilter` ./takescreenshot.c \
	  -lavcodec -lavformat -lavfilter -lavdevice -lswresample -lswscale -lavutil \
	  -o takescreenshot

transcoding: transcoding.c
	  gcc -g `pkg-config --cflags libavformat libavfilter` ./transcoding.c \
	  -lavcodec -lavformat -lavfilter -lavdevice -lswresample -lswscale -lavutil \
	  -o transcoding

scaling_video: scaling_video.c
	  gcc -g `pkg-config --cflags libavformat libavfilter` ./scaling_video.c \
	  -lavcodec -lavformat -lavfilter -lavdevice -lswresample -lswscale -lavutil \
	  -o scaling_video
