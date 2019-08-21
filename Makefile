CFLAGS = -O
#CFLAGS = -O -DRHEL3
#CFLAGS = -O -DJUSTCOPY

FILES=license.txt NOTICE gulp.c gulp.1 gulpman.html gulpman.pdf Makefile conv.c gulp.html changelog

gulp:	gulp.c 
	cc -g $(CFLAGS) gulp.c -o gulp -lpthread -lpcap

gulpman.html:	gulp.1
	nroff -man gulp.1 | bold2html > gulpman.html

gulp.tgz:	$(FILES)
	tar cvfz gulp.tgz $(FILES)

gulpman.pdf:	gulp.1
	groff -man gulp.1 > gulpman.ps && ps2pdf gulpman.ps && rm gulpman.ps
